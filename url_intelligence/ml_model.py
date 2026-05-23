from urllib.parse import urlparse
import threading
import traceback
import requests

try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

from url_intelligence.risk_engine import compute_risk_score

_bart_model = None
_bart_lock = threading.Lock()

_url_tokenizer = None
_url_model = None
_url_lock = threading.Lock()

TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "microsoft.com",
    "github.com",
    "openai.com",
    "apple.com",
    "amazon.com",
    "linkedin.com",
    "twitter.com",
    "instagram.com",
    "reddit.com",
    "wikipedia.org",
    "netflix.com",
    "stackoverflow.com",
]


def _extract_base_domain(url: str) -> str:
    try:
        if "://" not in url:
            url = f"http://{url}"
        hostname = urlparse(url).hostname or ""
        parts = hostname.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname
    except Exception:
        return ""


def _load_bart_model():
    global _bart_model
    if not _ML_AVAILABLE:
        return None
    if _bart_model is None:
        with _bart_lock:
            if _bart_model is None:
                print("[URL Intelligence] Loading BART zero-shot model (facebook/bart-large-mnli)...")
                _bart_model = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    device=-1
                )
                print("[URL Intelligence] BART model loaded.")
    return _bart_model


def _load_url_model():
    global _url_tokenizer, _url_model
    if not _ML_AVAILABLE:
        return None, None
    if _url_model is None:
        with _url_lock:
            if _url_model is None:
                model_name = "ealvaradob/bert-finetuned-phishing"
                print(f"[URL Intelligence] Loading URL phishing model ({model_name})...")
                _url_tokenizer = AutoTokenizer.from_pretrained(model_name)
                _url_model = AutoModelForSequenceClassification.from_pretrained(model_name)
                _url_model.eval()
                print("[URL Intelligence] URL phishing model loaded.")
    return _url_tokenizer, _url_model


def classify_url_ml(url: str) -> float:
    if not _ML_AVAILABLE:
        return 0.0
    try:
        tokenizer, model = _load_url_model()
        if tokenizer is None or model is None:
            return 0.0
        inputs = tokenizer(url, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        malicious_prob = probs[0][1].item() if probs.shape[1] > 1 else probs[0][0].item()
        return round(malicious_prob * 100, 2)
    except Exception as e:
        traceback.print_exc()
        print(f"[URL Intelligence] URL ML model error: {e}")
        return 0.0


def extract_page_text(url: str) -> str:
    try:
        if "://" not in url:
            url = f"http://{url}"
        from bs4 import BeautifulSoup
        resp = requests.get(url, timeout=3, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "meta", "link", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        return text[:2000]
    except Exception:
        return ""


def classify_content_semantic(text: str) -> float:
    if not _ML_AVAILABLE:
        return 0.0
    if not text or len(text.strip()) < 20:
        return 0.0
    try:
        model = _load_bart_model()
        if model is None:
            return 0.0
        candidate_labels = [
            "credential harvesting",
            "account verification phishing",
            "security alert scam",
            "fake login page",
            "benign website"
        ]
        result = model(text[:512], candidate_labels)
        label_scores = dict(zip(result["labels"], result["scores"]))
        malicious_score = (
            label_scores.get("credential harvesting", 0) +
            label_scores.get("account verification phishing", 0) +
            label_scores.get("security alert scam", 0) +
            label_scores.get("fake login page", 0)
        )
        return round(malicious_score * 100, 2)
    except Exception as e:
        traceback.print_exc()
        print(f"[URL Intelligence] BART content error: {e}")
        return 0.0


def classify_url_with_model(url: str) -> dict:
    try:
        base_domain = _extract_base_domain(url)
        if base_domain in TRUSTED_DOMAINS:
            print(f"[URL Check] Trusted domain: {base_domain} -> Safe")
            return {
                "risk_score": 0,
                "verdict": "Safe",
                "reason": "Trusted domain",
                "nudge_level": "none",
                "confidence": "Low",
                "features": {}
            }

        lexical_result = compute_risk_score(url)
        lexical_score = lexical_result.get("risk_score", 0)

        is_legit_brand = lexical_result.get("features", {}).get("is_legitimate_brand", 0)

        url_ml_score = classify_url_ml(url)

        if is_legit_brand:
            content_score = 0.0
        else:
            page_text = extract_page_text(url)
            content_score = classify_content_semantic(page_text)

        if content_score <= 1:
            final_score = round(
                (0.6 * lexical_score) +
                (0.4 * url_ml_score),
                2
            )
        else:
            final_score = round(
                (0.4 * lexical_score) +
                (0.3 * url_ml_score) +
                (0.3 * content_score),
                2
            )

        if lexical_score > 60 and url_ml_score > 85:
            final_score += 7
        if url_ml_score > 95:
            final_score += 5

        # Strong heuristic override
        features = lexical_result.get("features", {})
        if features.get('is_test_phishing', 0) or features.get('suspicious_form', 0):
            final_score = max(final_score, 99.0)

        final_score = min(final_score, 100.0)

        if final_score >= 85:
            verdict = "MALICIOUS"
            nudge_level = "block"
        elif final_score >= 60:
            verdict = "Suspicious"
            nudge_level = "warn"
        else:
            verdict = "Safe"
            nudge_level = "none"

        if final_score >= 90:
            confidence = "High"
        elif final_score >= 70:
            confidence = "Medium"
        else:
            confidence = "Low"

        lexical_reason = lexical_result.get("reason", "No suspicious lexical indicators detected")

        if verdict == "Safe":
            reason = "No phishing indicators detected."
        else:
            reason = (
                f"{lexical_reason} | "
                f"URL ML: {round(url_ml_score, 2)} | "
                f"Content: {round(content_score, 2)}"
            )

        print(f"[URL Check] {url}")
        print(f"  Lexical score:  {lexical_score}")
        print(f"  URL ML score:   {url_ml_score}")
        print(f"  Content score:  {content_score}")
        print(f"  Final score:    {final_score} -> {verdict} ({nudge_level}) [{confidence}]")

        # --- DEMO MODE: FORCE GENTLE NUDGE ---
        # Demo-only override for presentation purposes
        if "gentle-demo" in url.lower():
            final_score = 45.0
            verdict = "Suspicious"
            nudge_level = "warn"
            reason = "Demo mode: forced suspicious classification"

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "reason": reason,
            "nudge_level": nudge_level,
            "confidence": confidence,
            "features": lexical_result.get("features", {})
        }

    except Exception as e:
        traceback.print_exc()
        print(f"[URL Intelligence] Classification error: {e}")
        return {
            "risk_score": 0,
            "verdict": "Safe",
            "reason": "Classification unavailable",
            "nudge_level": "none",
            "confidence": "Low",
            "features": {}
        }

import numpy as np
import re
import math
from collections import Counter


FEATURE_NAMES = [
    'log_length',
    'token_count',
    'uppercase_ratio',
    'special_char_count',
    'has_base64',
    'entropy',
    'command_flag_count',
    'digit_ratio',
]

NUM_FEATURES = len(FEATURE_NAMES)

_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_CMD_FLAG_PATTERN = re.compile(r'\s-{1,2}[a-zA-Z]')


def extract_contextual_features(log_text: str) -> np.ndarray:
    length = len(log_text)
    tokens = log_text.split()
    token_count = len(tokens)

    upper_count = sum(1 for c in log_text if c.isupper())
    uppercase_ratio = upper_count / length if length > 0 else 0.0

    special_chars = set('!@#$%^&*(){}[]<>?/|\\~`+=;:\'\"')
    special_char_count = sum(1 for c in log_text if c in special_chars)

    has_base64 = 1.0 if _BASE64_PATTERN.search(log_text) else 0.0

    entropy = 0.0
    if length > 0:
        freq = Counter(log_text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

    command_flag_count = len(_CMD_FLAG_PATTERN.findall(log_text))

    digit_count = sum(1 for c in log_text if c.isdigit())
    digit_ratio = digit_count / length if length > 0 else 0.0

    return np.array([
        length,
        token_count,
        uppercase_ratio,
        special_char_count,
        has_base64,
        entropy,
        command_flag_count,
        digit_ratio,
    ], dtype=np.float64)


def extract_contextual_features_batch(texts) -> np.ndarray:
    return np.vstack([extract_contextual_features(t) for t in texts])

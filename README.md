# ILA-SOC (Intelligent Log Analytics & Security Operations Center)

ILA-SOC is a unified, highly optimized, and machine-learning-driven Security Operations Center (SOC) platform designed to ingest, process, and analyze endpoint and network security telemetry in real-time. By correlating logs with advanced ML classification ensembles and stateful heuristics, the system automates incident detection, alert triaging, and user awareness profiling.

---

## 🚀 Key Features

* **Real-time Threat Ingestion**: Built-in support for Sysmon logs and network flow telemetry.
* **Dual-Layer ML Ensemble**: Blends TF-IDF text models (SMOTE-balanced), Isolation Forest anomaly detectors, and XGBoost classifiers with contextual rules.
* **Sysmon Integration & Shadow Mode**: Silent, parallel log checking using an in-memory process lineage tracker to benchmark models safely in production.
* **Stateful Attack Tracking**: Automated detection of multi-stage attacks like credential dumping (Mimikatz), lateral movement, and slow, stateful reconnaissance.
* **Interactive Analyst Dashboard**: Features process execution tree visualizations, incident timelines, SLA tracking, and one-click mitigation controls.
* **Awareness profiling & Nudging**: Evaluates user activity risk to place them into cautious, impulsive, or negligent archetypes and applies security nudges.

---

## 📂 Project Documentation

This project contains detailed documentation to help you get started:
* **[DETAIL_OF_PROJECT.txt](DETAIL_OF_PROJECT.txt)**: Comprehensive architecture overview, database structures, machine learning features, folder explanations, and real-world use cases.
* **[HOW_TO_RUN.txt](HOW_TO_RUN.txt)**: End-to-end installation and run guide (Python setup, virtual environments, automatic database initialization, API usage, and troubleshooting tips).
* **[PROJECT_STRUCTURE.txt](PROJECT_STRUCTURE.txt)**: Detailed description of the clean directory structure.

---

## 🛠️ Tech Stack

* **Backend**: Flask 3.0, Flask-SocketIO (WebSockets), Werkzeug 3.0
* **Machine Learning**: Scikit-Learn, XGBoost, Pandas, NumPy, SciPy, Joblib
* **Database**: SQLite 3 (optimized indices, WAL mode)
* **Reporting**: FPDF2
* **Authentication**: JWT, Google OAuth 2.0
* **Deployment**: Docker, Docker Compose, Gunicorn

---

## 🏃 Quick Start

To run the application locally:

1. **Clone and Navigate**:
   ```bash
   git clone https://github.com/alimalik13/ILA-SOC.git
   cd ILA-SOC
   ```

2. **Setup Virtual Environment & Install Dependencies**:
   ```bash
   python -m venv .venv
   # Windows (PowerShell):
   .venv\Scripts\Activate.ps1
   # macOS/Linux:
   source .venv/bin/activate

   pip install -r requirements.txt
   ```

3. **Run Server**:
   ```bash
   python server.py
   ```
   Open your browser to [http://127.0.0.1:5000/login](http://127.0.0.1:5000/login).

*For a detailed production-grade guide, please refer to [HOW_TO_RUN.txt](HOW_TO_RUN.txt).*

---

## 📧 License & Authors
Developed by Ali Malik (ali.malik9545@gmail.com). Distributed under the MIT License.

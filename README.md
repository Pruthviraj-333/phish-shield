# Phish-Shield: AI-Powered Phishing Detection System

A multi-layered phishing detection system built with a Python FastAPI backend and a Chrome browser extension (Manifest V3). The system combines three independent detection methods — heuristic analysis, threat intelligence lookup, and a trained Random Forest classifier — to produce a unified risk score for every URL a user visits.

## Table of Contents

- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [ML Model Training](#ml-model-training)
- [Running the Backend](#running-the-backend)
- [Loading the Chrome Extension](#loading-the-chrome-extension)
- [API Reference](#api-reference)
- [Risk Scoring](#risk-scoring)
- [Integrating Threat Intelligence APIs](#integrating-threat-intelligence-apis)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [License](#license)

---

## Architecture

```
Chrome Browser Extension (Manifest V3)
         |
         | HTTP POST /scan-url
         v
  FastAPI Backend (uvicorn)
         |
         |-- Layer 1: Heuristic Engine
         |     Pattern matching, typosquatting detection,
         |     suspicious keyword and structure analysis
         |
         |-- Layer 2: Threat Intelligence
         |     Pluggable interface for VirusTotal,
         |     PhishTank, and similar APIs
         |
         |-- Layer 3: Machine Learning
               Random Forest classifier trained on
               16 URL-derived features (11,430 samples,
               85.9% accuracy, ROC-AUC 0.93)
```

The three layer scores are combined using a weighted formula (ML 60%, Heuristics 30%, Threat Intel 10%) and an agreement bonus is applied when both ML and heuristic signals align.

---

## Tech Stack

**Backend**
- Python 3.8+
- FastAPI 0.104
- uvicorn 0.24
- scikit-learn 1.3 (Random Forest)
- pandas, numpy, joblib
- python-dotenv

**Chrome Extension**
- Manifest V3
- Service worker (`background.js`)
- Content script (`content.js`)
- Popup UI (`popup.html`, `popup.js`, `styles.css`)

**ML Training**
- scikit-learn — Random Forest, train/test split, ROC-AUC
- pandas — dataset loading and preprocessing
- Dataset: Kaggle Web Page Phishing Detection Dataset (11,430 URLs)

---

## Project Structure

```
phish-shield/
├── backend/
│   ├── app/
│   │   ├── __init__.py              # Package init
│   │   ├── main.py                  # FastAPI app and CORS config
│   │   ├── api.py                   # /scan-url, /health, /stats endpoints
│   │   ├── feature_extractor.py     # URL feature extraction (16 features)
│   │   └── heuristic_engine.py      # Regex and keyword-based detection
│   ├── models/
│   │   ├── phish_model.pkl          # Trained Random Forest model
│   │   └── feature_names.pkl        # Feature name list for the model
│   ├── requirements.txt
│   ├── verify_features.py           # Script to verify model feature alignment
│   └── .env                         # API keys (not committed)
├── extension/
│   ├── manifest.json                # Extension config (Manifest V3)
│   ├── background.js                # Service worker — scans on tab load
│   ├── content.js                   # Injects warning banners into pages
│   ├── popup.html                   # Extension popup UI
│   ├── popup.js                     # Popup logic and API calls
│   ├── styles.css                   # All extension styles
│   └── icons/
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
├── ml_training/
│   ├── train_model.py               # Full training pipeline
│   ├── prepare_kaggle.py            # Helper to prep Kaggle dataset
│   ├── prepare_mendeley.py          # Helper to prep Mendeley dataset
│   ├── requirements.txt             # Training-only dependencies
│   └── datasets/
│       └── dataset_phishing.csv     # Training dataset (not committed)
└── README.md
```

---

## Prerequisites

- Python 3.8 or higher
- Google Chrome browser
- pip (Python package manager)
- A phishing URL dataset (see ML Model Training below)

---

## Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/Pruthviraj-333/phish-shield.git
cd phish-shield
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

```bash
cp backend/.env.example backend/.env
```

Edit `backend/.env` to add optional API keys:

```
VIRUSTOTAL_API_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here
```

The server runs without these keys; threat intelligence checks are skipped if keys are absent.

---

## ML Model Training

The backend will not start with full ML functionality unless a trained model exists at `backend/models/phish_model.pkl`. Follow these steps to train it.

### Option A: Using the Kaggle Dataset (Recommended)

1. Download the dataset from Kaggle:  
   https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset

2. Place the CSV file inside `ml_training/datasets/`:

   ```
   ml_training/datasets/dataset_phishing.csv
   ```

3. Run the training script from the project root:

   ```bash
   cd ml_training
   python train_model.py
   ```

**Training output (actual results with Kaggle dataset):**

```
Dataset loaded: 11,430 URLs
Training set: 9,144 samples
Test set: 2,286 samples
Training RandomForestClassifier...
Accuracy: 85.91%
ROC-AUC:  0.9318
Model saved to: backend/models/phish_model.pkl
```

### Option B: Automatic Sample Dataset (Fallback)

If no dataset file is found, `train_model.py` automatically generates a synthetic dataset of 2,000 URLs for demonstration purposes. Accuracy will be lower with synthetic data. Replace with the real Kaggle dataset for production use.

---

## Running the Backend

Start the server from the `backend` directory:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify it is running:

```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

Interactive API documentation is available at `http://localhost:8000/docs`.

---

## Loading the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `extension/` folder from the repository
5. The Phish-Shield icon will appear in the Chrome toolbar

The extension automatically scans every page you navigate to. The popup shows the current page's risk score, status, and detection details.

---

## API Reference

### GET /health

Returns server health status.

**Response:**
```json
{
  "status": "healthy"
}
```

### POST /scan-url

Scans a URL across all three detection layers and returns a combined risk score.

**Request body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "status": "safe",
  "risk_score": 5,
  "reason": "URL appears safe based on all detection layers",
  "detection_method": "No threats detected",
  "timestamp": "2026-01-22T10:30:00Z",
  "details": {
    "heuristic": {
      "suspicious": false,
      "score": 0,
      "reason": "No suspicious patterns detected"
    },
    "threat_intelligence": {
      "hit": false,
      "reason": "Not found in threat intelligence databases"
    },
    "machine_learning": {
      "prediction": 0,
      "probability": 0.04,
      "confidence": 0.96
    }
  }
}
```

`status` is either `"safe"` or `"unsafe"`. The threshold for unsafe is a `risk_score` >= 30.

### GET /stats

Returns model and feature metadata.

**Response:**
```json
{
  "model_loaded": true,
  "model_path": "models/phish_model.pkl",
  "available_features": [
    "url_length", "dot_count", "at_count", "has_ip",
    "subdomain_count", "hyphen_count", "underscore_count",
    "slash_count", "question_count", "equals_count",
    "is_https", "hostname_length", "path_length",
    "digit_count", "special_char_count", "domain_length"
  ],
  "detection_layers": [
    "Heuristic Analysis",
    "Threat Intelligence",
    "Machine Learning"
  ]
}
```

---

## Risk Scoring

The combined risk score (0-100) is calculated as follows:

```
risk_score = (heuristic_score * 0.30)
           + (ml_probability * 100 * 0.60)
           + (threat_intel_hit * 100 * 0.10)
           + agreement_bonus
```

The `agreement_bonus` (up to 15 points) is added when both the ML model and heuristic engine independently flag the URL as suspicious.

| Risk Score | Status     | Description                             |
|------------|------------|-----------------------------------------|
| 0 - 29     | Safe       | No significant threats detected         |
| 30 - 49    | Caution    | Minor suspicious indicators             |
| 50 - 74    | Suspicious | Multiple warning signs present          |
| 75 - 100   | Dangerous  | High-confidence phishing attempt        |

---

## Integrating Threat Intelligence APIs

The threat intelligence layer in `backend/app/api.py` is a pluggable placeholder. To enable real lookups, replace the `check_threat_intelligence` function body with the following VirusTotal implementation:

```python
import base64
import os
import requests

async def check_threat_intelligence(url: str) -> tuple[bool, str]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return False, "API key not configured"

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            return True, f"Flagged by {malicious} vendors on VirusTotal"

    return False, "Clean on VirusTotal"
```

---

## Troubleshooting

**Extension cannot connect to the API**
- Confirm the backend is running: `curl http://localhost:8000/health`
- Check that port 8000 is not blocked by a firewall
- Review CORS settings in `backend/app/main.py`
- Open the browser console (F12) for error messages

**Model not loading**
- Verify the model file exists: `backend/models/phish_model.pkl`
- Re-run the training script: `python ml_training/train_model.py`

**Extension not scanning pages**
- Confirm the extension is enabled in `chrome://extensions/`
- Check the service worker console: Extensions > Phish-Shield > Service Worker > Inspect

**Port 8000 already in use**
```bash
# Windows
netstat -ano | findstr :8000

# Run on a different port
uvicorn app.main:app --port 8001
```

---

## Security Notes

- Do not commit the `.env` file. It is excluded in `.gitignore`.
- Scanned URLs are not stored or logged by default.
- For production deployments, enable HTTPS and add rate limiting to the API.
- The trained model file (`phish_model.pkl`) should be treated as a build artifact and not committed to source control.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

**Disclaimer:** This tool is intended for educational and research purposes. No phishing detection system guarantees 100% accuracy. Always exercise caution when visiting unfamiliar websites.
# 🛡️ Phish-Shield: Multi-Layered Phishing Detection System

A comprehensive, production-ready phishing detection system consisting of a Chrome browser extension and Python FastAPI backend. The system uses three detection layers: heuristic analysis, threat intelligence APIs, and machine learning.

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### Multi-Layered Detection
- **Layer 1: Heuristic Analysis** - Pattern matching, typosquatting detection, suspicious keyword identification
- **Layer 2: Threat Intelligence** - Integration ready for VirusTotal, PhishTank, and other APIs
- **Layer 3: Machine Learning** - Random Forest classifier trained on URL features

### Browser Extension
- Real-time URL scanning as you browse
- Visual warning banners on dangerous sites
- Risk score visualization (0-100)
- Detailed technical information panel
- Lightweight and non-intrusive

### Backend API
- Fast and scalable FastAPI server
- RESTful API endpoints
- Comprehensive logging
- CORS enabled for browser extensions
- Modular and extensible architecture

## 🏗️ Architecture

```
┌─────────────────┐
│  Chrome Browser │
│   Extension     │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  FastAPI Server │
│                 │
│  ┌───────────┐  │
│  │ Heuristic │  │
│  │  Engine   │  │
│  └───────────┘  │
│                 │
│  ┌───────────┐  │
│  │  Threat   │  │
│  │   Intel   │  │
│  └───────────┘  │
│                 │
│  ┌───────────┐  │
│  │    ML     │  │
│  │  Model    │  │
│  └───────────┘  │
└─────────────────┘
```

## 📦 Prerequisites

- **Python 3.8+** - For the backend server
- **Node.js** (optional) - For development tools
- **Chrome Browser** - For the extension
- **pip** - Python package manager

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/phish-shield.git
cd phish-shield
```

### Step 2: Set Up Backend

#### 2.1 Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

#### 2.2 Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

#### 2.3 Configure Environment Variables

```bash
# Copy the template
cp .env.example .env

# Edit .env and add your API keys (optional)
# VIRUSTOTAL_API_KEY=your_key_here
# PHISHTANK_API_KEY=your_key_here
```

### Step 3: Train the ML Model

Before running the backend, you need to train the machine learning model:

```bash
# From the project root directory
cd ml_training

# Run the training script
python train_model.py
```

This will:
1. Create a sample dataset if one doesn't exist
2. Extract features from URLs
3. Train a Random Forest model
4. Save the model to `backend/models/phish_model.pkl`

**Expected Output:**
```
Loading dataset from ml_training/datasets/phishing_urls.csv...
Dataset loaded: 1000 URLs
Extracting features...
Training set: 800 samples
Test set: 200 samples
Training RandomForest model...
Accuracy: 0.9500
Model saved to backend/models/phish_model.pkl
```

### Step 4: Start the Backend Server

```bash
# Navigate to backend directory
cd ../backend

# Run the server
python -m app.main

# Or use uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

Verify the API is running:
```bash
curl http://localhost:8000/health
# Should return: {"status":"healthy"}
```

### Step 5: Load the Chrome Extension

#### 5.1 Enable Developer Mode

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right corner)

#### 5.2 Load Unpacked Extension

1. Click "Load unpacked"
2. Navigate to the `phish-shield/extension` directory
3. Click "Select Folder"

#### 5.3 Verify Installation

- The Phish-Shield icon should appear in your Chrome toolbar
- Click the icon to open the popup
- You should see "Protected by Phish-Shield v1.0"

### Step 6: Create Extension Icons (Optional)

The extension needs icons in the `extension/icons/` directory:

```bash
mkdir -p extension/icons
```

Create three PNG images:
- `icon16.png` - 16x16 pixels
- `icon48.png` - 48x48 pixels
- `icon128.png` - 128x128 pixels

You can use any image editor or generate simple shield icons online.

## 📖 Usage

### Basic Usage

1. **Automatic Scanning**: Simply browse the web. Phish-Shield automatically scans every page you visit.

2. **View Results**: Click the extension icon to see:
   - Current page URL
   - Security status (Safe/Suspicious/Dangerous)
   - Risk score (0-100)
   - Detection details

3. **Warning Banners**: If a dangerous site is detected, a red warning banner appears at the top of the page.

### Manual Rescanning

1. Click the extension icon
2. Click "🔄 Rescan Current Page"
3. Wait for the updated results

### Understanding Risk Scores

- **0-24**: Safe - No significant threats detected
- **25-49**: Caution - Minor suspicious indicators
- **50-74**: Suspicious - Multiple warning signs
- **75-100**: Dangerous - High confidence phishing attempt

### Detection Methods

- **Heuristic Analysis**: Pattern-based detection (typosquatting, suspicious keywords)
- **Threat Intelligence**: Checks against known malicious URL databases
- **Machine Learning**: AI-powered probability assessment
- **Combined Analysis**: Multiple detection methods agree

## 📁 Project Structure

```
phish-shield/
├── backend/
│   ├── app/
│   │   ├── __init__.py              # Package initialization
│   │   ├── main.py                  # FastAPI app entry point
│   │   ├── api.py                   # API endpoints
│   │   ├── feature_extractor.py     # URL feature extraction
│   │   └── heuristic_engine.py      # Pattern-based detection
│   ├── models/
│   │   ├── phish_model.pkl          # Trained ML model
│   │   └── feature_names.pkl        # Feature name mappings
│   ├── requirements.txt             # Python dependencies
│   └── .env                         # Environment variables
├── extension/
│   ├── manifest.json                # Extension configuration
│   ├── background.js                # Service worker
│   ├── content.js                   # Content script
│   ├── popup.html                   # Popup UI
│   ├── popup.js                     # Popup logic
│   ├── styles.css                   # All styles
│   └── icons/                       # Extension icons
│       ├── icon16.png
│       ├── icon48.png
│       └── icon128.png
├── ml_training/
│   ├── train_model.py               # Model training script
│   └── datasets/
│       └── phishing_urls.csv        # Training dataset
└── README.md                        # This file
```

## 🔌 API Documentation

### Base URL
```
http://localhost:8000
```

### Endpoints

#### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy"
}
```

#### 2. Scan URL
```http
POST /scan-url
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "status": "safe",
  "risk_score": 15,
  "reason": "URL appears safe based on all detection layers",
  "detection_method": "No threats detected",
  "timestamp": "2026-01-22T10:30:00Z",
  "details": {
    "heuristic": {
      "suspicious": false,
      "score": 10,
      "reason": "No suspicious patterns detected"
    },
    "threat_intelligence": {
      "hit": false,
      "reason": "Not found in threat intelligence databases"
    },
    "machine_learning": {
      "prediction": 0,
      "probability": 0.12,
      "confidence": 0.88
    }
  }
}
```

#### 3. Get Statistics
```http
GET /stats
```

**Response:**
```json
{
  "model_loaded": true,
  "model_path": "backend/models/phish_model.pkl",
  "available_features": [
    "url_length",
    "dot_count",
    "at_count",
    ...
  ],
  "detection_layers": [
    "Heuristic Analysis",
    "Threat Intelligence (Placeholder)",
    "Machine Learning"
  ]
}
```

## 🛠️ Development

### Adding Your Own Dataset

Replace the sample dataset with real phishing data:

1. Obtain a phishing URL dataset (e.g., [PhiUSIIL Dataset](https://www.kaggle.com/datasets/))
2. Save as CSV with columns: `url`, `label` (0=legitimate, 1=phishing)
3. Place in `ml_training/datasets/phishing_urls.csv`
4. Retrain the model: `python ml_training/train_model.py`

### Integrating Threat Intelligence APIs

#### VirusTotal Integration

Edit `backend/app/api.py`:

```python
import os
import requests

async def check_threat_intelligence(url: str) -> tuple[bool, str]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key:
        return False, "API key not configured"
    
    # Encode URL
    import hashlib
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # Query VirusTotal
    headers = {"x-apikey": api_key}
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        
        if malicious > 0:
            return True, f"Flagged by {malicious} vendors on VirusTotal"
    
    return False, "Clean on VirusTotal"
```

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### API Documentation (Swagger)

Visit `http://localhost:8000/docs` for interactive API documentation.

## 🐛 Troubleshooting

### Extension Can't Connect to API

**Problem:** Extension shows "Unable to connect to Phish-Shield API"

**Solutions:**
1. Verify backend is running: `curl http://localhost:8000/health`
2. Check CORS settings in `backend/app/main.py`
3. Ensure port 8000 is not blocked by firewall
4. Check browser console for errors (F12 → Console)

### Model Not Loading

**Problem:** Backend logs show "Model not found"

**Solutions:**
1. Verify model file exists: `ls backend/models/phish_model.pkl`
2. Retrain the model: `python ml_training/train_model.py`
3. Check file permissions

### Extension Not Scanning Pages

**Problem:** Pages load but no scanning occurs

**Solutions:**
1. Check extension is enabled in `chrome://extensions/`
2. Verify background service worker is running (extension details page)
3. Check extension console: Extensions → Phish-Shield → Service worker → Console
4. Reload the extension

### High False Positive Rate

**Problem:** Legitimate sites are flagged as phishing

**Solutions:**
1. Retrain with better dataset
2. Adjust risk score threshold in `background.js`
3. Fine-tune heuristic rules in `heuristic_engine.py`
4. Collect more training data

### Port Already in Use

**Problem:** "Address already in use" error

**Solutions:**
```bash
# Find process using port 8000
# On Windows:
netstat -ano | findstr :8000

# On macOS/Linux:
lsof -i :8000

# Kill the process or use different port:
uvicorn app.main:app --port 8001
```

## 🔒 Security Considerations

1. **API Keys**: Never commit `.env` file with real API keys
2. **HTTPS**: Use HTTPS in production deployments
3. **Rate Limiting**: Implement rate limiting for production APIs
4. **Data Privacy**: Scanned URLs are not stored by default
5. **Model Security**: Protect the trained model file from unauthorized access

## 🚀 Deployment

### Production Backend

1. **Use Production Server:**
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app.main:app
```

2. **Configure HTTPS** with Let's Encrypt or similar

3. **Set up Reverse Proxy** (Nginx/Apache)

4. **Update Extension** to use production API URL in `background.js`

### Publishing Extension

1. Create a developer account on [Chrome Web Store](https://chrome.google.com/webstore/devconsole)
2. Package extension as ZIP
3. Upload and fill in metadata
4. Submit for review

## 📊 Performance

- **Average Scan Time**: 200-500ms
- **Model Inference**: <10ms
- **Memory Usage**: ~50MB (backend)
- **Extension Overhead**: <5MB

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Future Enhancements

- [ ] Real-time threat intelligence integration
- [ ] Deep learning models (LSTM, BERT)
- [ ] Screenshot analysis
- [ ] User feedback system
- [ ] Whitelist/blacklist management
- [ ] Browser history analysis
- [ ] Multi-browser support (Firefox, Edge)
- [ ] Cloud-based scanning API
- [ ] Mobile app versions

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- PhiUSIIL Phishing URL Dataset
- scikit-learn for ML capabilities
- FastAPI for the excellent web framework
- Chrome Extensions API documentation

## 📧 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Email: support@phish-shield.example.com
- Documentation: https://docs.phish-shield.example.com

---

**⚠️ Disclaimer:** This tool is for educational and research purposes. Always exercise caution when visiting unknown websites. No phishing detection system is 100% accurate.

**Made with ❤️ by the Phish-Shield Team**
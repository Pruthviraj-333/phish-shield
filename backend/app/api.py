"""
API Endpoints for Phishing Detection
Handles URL scanning requests with multi-layered detection
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl
import joblib
import os
from typing import Optional
import logging
from datetime import datetime

from app.feature_extractor import URLFeatureExtractor
from app.heuristic_engine import HeuristicEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# Load ML model at startup
# Handle both running from project root and from backend directory
import sys
if os.path.exists("backend/models/phish_model.pkl"):
    MODEL_PATH = "backend/models/phish_model.pkl"
elif os.path.exists("models/phish_model.pkl"):
    MODEL_PATH = "models/phish_model.pkl"
elif os.path.exists("../backend/models/phish_model.pkl"):
    MODEL_PATH = "../backend/models/phish_model.pkl"
else:
    MODEL_PATH = "models/phish_model.pkl"  # Default fallback

model = None
feature_extractor = URLFeatureExtractor()
heuristic_engine = HeuristicEngine()

try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        logger.info("ML model loaded successfully")
    else:
        logger.warning(f"Model not found at {MODEL_PATH}. ML detection will be disabled.")
except Exception as e:
    logger.error(f"Error loading model: {e}")
    model = None

# Request/Response models
class URLScanRequest(BaseModel):
    """Request model for URL scanning"""
    url: str
    
class URLScanResponse(BaseModel):
    """Response model for URL scanning"""
    url: str
    status: str  # "safe" or "unsafe"
    risk_score: int  # 0-100
    reason: str
    detection_method: str
    timestamp: str
    details: Optional[dict] = None

async def check_threat_intelligence(url: str) -> tuple[bool, str]:
    """
    Layer 2: Check external threat intelligence APIs
    
    This is a placeholder for VirusTotal, PhishTank, or similar API integration.
    In production, you would make actual API calls here.
    
    Args:
        url: The URL to check
        
    Returns:
        Tuple of (is_malicious, reason)
    """
    # TODO: Implement actual API calls
    # Example with VirusTotal:
    # api_key = os.getenv("VIRUSTOTAL_API_KEY")
    # if api_key:
    #     response = requests.get(
    #         f"https://www.virustotal.com/api/v3/urls/{url_id}",
    #         headers={"x-apikey": api_key}
    #     )
    #     ...
    
    # Placeholder: Always return safe for now
    logger.info(f"Threat intelligence check for {url} (placeholder)")
    return False, "Not found in threat intelligence databases"

def calculate_risk_score(heuristic_score: int, ml_probability: float, threat_intel_hit: bool) -> int:
    """
    Calculate combined risk score from all detection layers
    
    Args:
        heuristic_score: Score from heuristic engine (0-100)
        ml_probability: Probability from ML model (0-1)
        threat_intel_hit: Whether threat intelligence found the URL
        
    Returns:
        Combined risk score (0-100)
    """
    # Weight the different components
    weighted_heuristic = heuristic_score * 0.4
    weighted_ml = (ml_probability * 100) * 0.4
    weighted_threat = 100 if threat_intel_hit else 0
    weighted_threat *= 0.2
    
    # Calculate final score
    final_score = int(weighted_heuristic + weighted_ml + weighted_threat)
    return min(100, max(0, final_score))

@router.post("/scan-url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """
    Scan a URL for phishing indicators using multi-layered detection
    
    Detection Layers:
    1. Heuristic analysis (regex, typosquatting)
    2. Threat intelligence APIs (VirusTotal, PhishTank)
    3. Machine learning model
    
    Args:
        request: URLScanRequest containing the URL to scan
        
    Returns:
        URLScanResponse with detection results
    """
    url = request.url
    logger.info(f"Scanning URL: {url}")
    
    try:
        # Initialize response data
        detection_details = {}
        reasons = []
        
        # LAYER 1: Heuristic Analysis
        logger.info("Layer 1: Running heuristic checks...")
        is_suspicious_heuristic, heuristic_reason, heuristic_score = heuristic_engine.check_url(url)
        
        detection_details['heuristic'] = {
            'suspicious': is_suspicious_heuristic,
            'score': heuristic_score,
            'reason': heuristic_reason
        }
        
        if is_suspicious_heuristic:
            reasons.append(f"Heuristic: {heuristic_reason}")
        
        # LAYER 2: Threat Intelligence
        logger.info("Layer 2: Checking threat intelligence...")
        threat_intel_hit, threat_intel_reason = await check_threat_intelligence(url)
        
        detection_details['threat_intelligence'] = {
            'hit': threat_intel_hit,
            'reason': threat_intel_reason
        }
        
        if threat_intel_hit:
            reasons.append(f"Threat Intel: {threat_intel_reason}")
        
        # LAYER 3: Machine Learning
        ml_probability = 0.0
        ml_prediction = 0
        
        if model is not None:
            logger.info("Layer 3: Running ML prediction...")
            try:
                # Extract features
                features = feature_extractor.extract_features_vector(url)
                
                # Get prediction and probability
                ml_prediction = model.predict(features)[0]
                ml_probabilities = model.predict_proba(features)[0]
                ml_probability = ml_probabilities[1]  # Probability of phishing class
                
                detection_details['machine_learning'] = {
                    'prediction': int(ml_prediction),
                    'probability': float(ml_probability),
                    'confidence': float(max(ml_probabilities))
                }
                
                if ml_prediction == 1:  # Phishing detected
                    reasons.append(f"ML Model: {ml_probability*100:.1f}% confidence of phishing")
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
                detection_details['machine_learning'] = {'error': str(e)}
        else:
            detection_details['machine_learning'] = {'status': 'Model not loaded'}
        
        # Calculate combined risk score
        risk_score = calculate_risk_score(heuristic_score, ml_probability, threat_intel_hit)
        
        # Determine final status (threshold: 50)
        is_unsafe = risk_score >= 50
        status = "unsafe" if is_unsafe else "safe"
        
        # Determine primary detection method
        if threat_intel_hit:
            detection_method = "Threat Intelligence"
        elif is_suspicious_heuristic and heuristic_score >= 60:
            detection_method = "Heuristic Analysis"
        elif ml_prediction == 1 and ml_probability > 0.7:
            detection_method = "Machine Learning"
        elif is_unsafe:
            detection_method = "Combined Analysis"
        else:
            detection_method = "No threats detected"
        
        # Compile reason
        if reasons:
            final_reason = "; ".join(reasons)
        else:
            final_reason = "URL appears safe based on all detection layers"
        
        # Create response
        response = URLScanResponse(
            url=url,
            status=status,
            risk_score=risk_score,
            reason=final_reason,
            detection_method=detection_method,
            timestamp=datetime.utcnow().isoformat(),
            details=detection_details
        )
        
        logger.info(f"Scan complete: {status} (risk: {risk_score})")
        return response
        
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")

@router.get("/stats")
async def get_stats():
    """Get API statistics and model information"""
    return {
        "model_loaded": model is not None,
        "model_path": MODEL_PATH,
        "available_features": feature_extractor.get_feature_names(),
        "detection_layers": [
            "Heuristic Analysis",
            "Threat Intelligence (Placeholder)",
            "Machine Learning" if model else "Machine Learning (Disabled)"
        ]
    }
"""
Verify that feature extractor matches the trained model
Run this after updating feature_extractor.py
"""

import sys
import os
sys.path.append('backend')

from app.feature_extractor import URLFeatureExtractor
import joblib

def verify_features():
    """Check feature compatibility"""
    
    print("=" * 70)
    print("FEATURE COMPATIBILITY CHECK")
    print("=" * 70)
    
    # Initialize extractor
    extractor = URLFeatureExtractor()
    
    # Check model exists
    model_path = "models/phish_model.pkl"
    
    if not os.path.exists(model_path):
        print("\n❌ Model not found at:", model_path)
        print("\nPlease train the model first:")
        print("  cd ml_training")
        print("  python train_model.py")
        return False
    
    # Load model
    print("\nLoading model...")
    model = joblib.load(model_path)
    
    # Get expected features from model
    expected_features = model.n_features_in_
    
    # Get features from extractor
    test_url = "https://www.example.com/test?id=123#section"
    features = extractor.extract_features(test_url)
    actual_features = len(features)
    
    print(f"\n✓ Model loaded from: {model_path}")
    print(f"\nFeature Count Comparison:")
    print(f"  Expected (Model):    {expected_features} features")
    print(f"  Actual (Extractor):  {actual_features} features")
    
    if expected_features == actual_features:
        print(f"\n✅ SUCCESS: Feature counts match!")
    else:
        print(f"\n❌ ERROR: Feature count mismatch!")
        print(f"\n  Difference: {abs(expected_features - actual_features)} features")
        
        if expected_features > actual_features:
            print(f"  Missing: {expected_features - actual_features} features")
            print("\n  ACTION REQUIRED:")
            print("  - Update backend/app/feature_extractor.py to extract more features")
        else:
            print(f"  Extra: {actual_features - expected_features} features")
            print("\n  ACTION REQUIRED:")
            print("  - Retrain the model with new features:")
            print("    cd ml_training")
            print("    python train_model.py")
        
        return False
    
    # Show feature list
    print("\nFeature List:")
    print("-" * 70)
    for i, (name, value) in enumerate(features.items(), 1):
        print(f"  {i:2}. {name:<20} = {value}")
    
    # Test prediction
    print("\n" + "=" * 70)
    print("TESTING PREDICTION")
    print("=" * 70)
    
    print(f"\nTest URL: {test_url}")
    
    try:
        features_vector = extractor.extract_features_vector(test_url)
        prediction = model.predict(features_vector)[0]
        probabilities = model.predict_proba(features_vector)[0]
        
        print(f"\n✅ Prediction successful!")
        print(f"  Classification: {'Phishing' if prediction == 1 else 'Legitimate'}")
        print(f"  Confidence: {max(probabilities)*100:.1f}%")
        print(f"  Phishing Probability: {probabilities[1]*100:.1f}%")
        
    except Exception as e:
        print(f"\n❌ Prediction failed!")
        print(f"  Error: {e}")
        return False
    
    # Test with common URLs
    print("\n" + "=" * 70)
    print("TESTING WITH COMMON URLs")
    print("=" * 70)
    
    test_urls = [
        ("https://www.google.com", "Safe"),
        ("https://www.facebook.com", "Safe"),
        ("http://paypal-verify.tk", "Phishing"),
        ("http://192.168.1.1/login", "Phishing"),
    ]
    
    print(f"\n{'URL':<40} {'Expected':<12} {'Prediction':<12} {'Prob':<8} {'Status'}")
    print("-" * 80)
    
    all_passed = True
    for url, expected in test_urls:
        try:
            features_vector = extractor.extract_features_vector(url)
            prediction = model.predict(features_vector)[0]
            prob = model.predict_proba(features_vector)[0][1]
            
            predicted = "Phishing" if prediction == 1 else "Safe"
            status = "✅" if predicted == expected else "⚠️"
            
            print(f"{url:<40} {expected:<12} {predicted:<12} {prob*100:>5.1f}%  {status}")
            
            if predicted != expected:
                all_passed = False
                
        except Exception as e:
            print(f"{url:<40} {expected:<12} ERROR        -      ❌")
            print(f"  Error: {e}")
            all_passed = False
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    if expected_features == actual_features and all_passed:
        print("\n✅ ALL CHECKS PASSED!")
        print("\nYour system is ready to use:")
        print("  1. Feature extractor matches model ✓")
        print("  2. Predictions working correctly ✓")
        print("  3. Test cases passing ✓")
        print("\nNext: Restart your backend server")
        print("  cd backend")
        print("  python -m app.main")
        return True
    else:
        print("\n❌ CHECKS FAILED!")
        print("\nPlease fix the issues above before proceeding.")
        return False

if __name__ == "__main__":
    success = verify_features()
    exit(0 if success else 1)
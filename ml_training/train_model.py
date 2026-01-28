"""
ML Training Script for Phishing URL Detection
Optimized for Kaggle Web Page Phishing Detection Dataset
Dataset: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
import joblib
import re
from urllib.parse import urlparse
import os
import warnings
warnings.filterwarnings('ignore')

class URLFeatureExtractor:
    """Extract features from URLs for ML model training"""
    
    @staticmethod
    def extract_features(url):
        """Extract numerical features from a URL"""
        features = {}
        
        # Convert to string and handle NaN values
        url = str(url).strip()
        if url == 'nan' or url == '':
            url = 'http://empty.com'
        
        # Basic URL length
        features['url_length'] = len(url)
        
        # Count of dots
        features['dot_count'] = url.count('.')
        
        # Count of @ symbols
        features['at_count'] = url.count('@')
        
        # Check for IP address in URL
        ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
        
        # Count of subdomains
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            hostname = parsed.hostname or ''
            parts = hostname.split('.')
            features['subdomain_count'] = max(0, len(parts) - 2)
        except:
            features['subdomain_count'] = 0
        
        # Count of hyphens (common in phishing)
        features['hyphen_count'] = url.count('-')
        
        # Count of underscores
        features['underscore_count'] = url.count('_')
        
        # Count of slashes
        features['slash_count'] = url.count('/')
        
        # Count of question marks
        features['question_count'] = url.count('?')
        
        # Count of equals signs
        features['equals_count'] = url.count('=')
        
        # Check for HTTPS
        features['is_https'] = 1 if url.startswith('https://') else 0
        
        # Length of hostname
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            features['hostname_length'] = len(parsed.hostname or '')
        except:
            features['hostname_length'] = 0
        
        # Count of digits
        features['digit_count'] = sum(c.isdigit() for c in url)
        
        # Count of letters
        features['letter_count'] = sum(c.isalpha() for c in url)
        
        # Additional features for better accuracy
        features['has_port'] = 1 if ':' in url.split('/')[-1] else 0
        features['has_fragment'] = 1 if '#' in url else 0
        
        return features

def load_and_prepare_data(csv_path):
    """Load CSV and prepare features"""
    print(f"Loading dataset from {csv_path}...")
    
    # Read CSV
    df = pd.read_csv(csv_path)
    
    # Handle different column name variations
    # Kaggle dataset might use 'url' or 'URL', 'label' or 'Label'
    url_col = None
    label_col = None
    
    for col in df.columns:
        if col.lower() in ['url', 'urls', 'link']:
            url_col = col
        if col.lower() in ['label', 'class', 'type', 'status']:
            label_col = col
    
    if url_col is None or label_col is None:
        print(f"Error: Could not find URL or label columns")
        print(f"Available columns: {df.columns.tolist()}")
        return None, None
    
    print(f"Using columns: URL='{url_col}', Label='{label_col}'")
    
    # Create clean dataframe
    df = df[[url_col, label_col]].copy()
    df.columns = ['url', 'label']
    
    # Remove NaN values
    df = df.dropna()
    
    # Convert labels to int if needed
    df['label'] = df['label'].astype(int)
    
    print(f"✓ Dataset loaded: {len(df):,} URLs")
    print(f"\nClass Distribution:")
    print(df['label'].value_counts().sort_index())
    print(f"\nBalance: {df['label'].value_counts(normalize=True).to_dict()}")
    
    # Extract features for each URL
    print("\nExtracting features from URLs...")
    extractor = URLFeatureExtractor()
    
    features_list = []
    total = len(df)
    
    for idx, url in enumerate(df['url']):
        if idx % 10000 == 0 and idx > 0:
            print(f"  Progress: {idx:,}/{total:,} ({idx/total*100:.1f}%)")
        features_list.append(extractor.extract_features(url))
    
    print(f"✓ Feature extraction complete: {total:,}/{total:,} (100.0%)\n")
    
    # Convert to DataFrame
    features_df = pd.DataFrame(features_list)
    
    print("Extracted Features Summary:")
    print(features_df.describe())
    print()
    
    return features_df, df['label']

def train_model(X, y):
    """Train RandomForest model with optimized hyperparameters"""
    print("=" * 70)
    print("TRAINING MACHINE LEARNING MODEL")
    print("=" * 70)
    
    print("\nSplitting data into train/test sets (80/20 split)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"✓ Training set: {len(X_train):,} samples")
    print(f"✓ Test set: {len(X_test):,} samples")
    
    # Calculate class weights for balanced learning
    class_counts = y_train.value_counts()
    total = len(y_train)
    class_weight = {
        0: total / (2 * class_counts[0]),
        1: total / (2 * class_counts[1])
    }
    
    print(f"\nClass weights (for balanced learning):")
    print(f"  Class 0 (Legitimate): {class_weight[0]:.3f}")
    print(f"  Class 1 (Phishing): {class_weight[1]:.3f}")
    
    print("\nTraining RandomForest Classifier...")
    print("Hyperparameters:")
    print("  - n_estimators: 150")
    print("  - max_depth: 25")
    print("  - min_samples_split: 10")
    print("  - min_samples_leaf: 4")
    print("  - class_weight: balanced")
    print("\nThis may take 5-10 minutes...\n")
    
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=10,
        min_samples_leaf=4,
        class_weight=class_weight,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X_train, y_train)
    
    print("\n✓ Training complete!\n")
    
    print("=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)
    
    print("\nMaking predictions on test set...")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\n🎯 ACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"📊 ROC-AUC SCORE: {roc_auc:.4f}\n")
    
    print("Classification Report:")
    print("-" * 70)
    print(classification_report(y_test, y_pred, 
                                target_names=['Legitimate', 'Phishing'],
                                digits=4))
    
    print("\nConfusion Matrix:")
    print("-" * 70)
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted Legitimate  |  Predicted Phishing")
    print(f"Actual Legitimate:      {cm[0][0]:>6,}        |      {cm[0][1]:>6,}")
    print(f"Actual Phishing:        {cm[1][0]:>6,}        |      {cm[1][1]:>6,}")
    print()
    
    # Calculate additional metrics
    tn, fp, fn, tp = cm.ravel()
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    print("Detailed Metrics:")
    print("-" * 70)
    print(f"True Positives:  {tp:>6,} (Correctly identified phishing)")
    print(f"True Negatives:  {tn:>6,} (Correctly identified legitimate)")
    print(f"False Positives: {fp:>6,} (Legitimate marked as phishing)")
    print(f"False Negatives: {fn:>6,} (Phishing marked as legitimate)")
    print(f"\nPrecision: {precision:.4f} (How many flagged sites are actually phishing)")
    print(f"Recall:    {recall:.4f} (How many phishing sites we catch)")
    print(f"F1-Score:  {f1:.4f} (Harmonic mean of precision and recall)")
    print(f"FPR:       {fpr:.4f} (False positive rate - lower is better)")
    print()
    
    # Feature importance
    print("\n" + "=" * 70)
    print("FEATURE IMPORTANCE ANALYSIS")
    print("=" * 70)
    
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nTop 10 Most Important Features:")
    print("-" * 70)
    for idx, row in feature_importance.head(10).iterrows():
        bar = '█' * int(row['importance'] * 100)
        print(f"{row['feature']:.<25} {row['importance']:.4f} {bar}")
    print()
    
    # Performance assessment
    print("\n" + "=" * 70)
    print("PERFORMANCE ASSESSMENT")
    print("=" * 70)
    
    if accuracy >= 0.93:
        print("\n✅ EXCELLENT: Model performance is outstanding!")
        print("   - Ready for production deployment")
        print("   - High accuracy with good balance")
    elif accuracy >= 0.90:
        print("\n✅ VERY GOOD: Model performance is strong")
        print("   - Suitable for production use")
        print("   - Consider fine-tuning for edge cases")
    elif accuracy >= 0.85:
        print("\n⚠️  GOOD: Model performance is acceptable")
        print("   - May need additional training data")
        print("   - Monitor false positives in production")
    else:
        print("\n⚠️  NEEDS IMPROVEMENT: Model accuracy is below target")
        print("   - Consider collecting more training data")
        print("   - Try different feature engineering")
    
    if fpr < 0.05:
        print(f"   - Low false positive rate ({fpr:.2%}) - Excellent! ✅")
    elif fpr < 0.10:
        print(f"   - Moderate false positive rate ({fpr:.2%}) - Acceptable ⚠️")
    else:
        print(f"   - High false positive rate ({fpr:.2%}) - Needs attention ❌")
    
    return model, feature_importance

def save_model(model, feature_importance, output_path):
    """Save trained model to disk"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save model
    joblib.dump(model, output_path)
    print(f"✓ Model saved to: {output_path}")
    
    # Get file size
    file_size = os.path.getsize(output_path) / (1024 * 1024)
    print(f"✓ Model size: {file_size:.2f} MB")
    
    # Save feature names
    feature_names_path = output_path.replace('phish_model.pkl', 'feature_names.pkl')
    joblib.dump(list(feature_importance['feature']), feature_names_path)
    print(f"✓ Feature names saved to: {feature_names_path}")
    
    # Save feature importance
    importance_path = output_path.replace('phish_model.pkl', 'feature_importance.csv')
    feature_importance.to_csv(importance_path, index=False)
    print(f"✓ Feature importance saved to: {importance_path}")

def main():
    """Main training pipeline"""
    print("\n" + "=" * 70)
    print("PHISH-SHIELD ML MODEL TRAINING")
    print("=" * 70)
    print("\nOptimized for Kaggle Web Page Phishing Detection Dataset")
    print("Dataset: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset\n")
    
    # Paths
    dataset_path = 'D:\phish-shield\ml_training\datasets'
    model_output_path = 'backend/models/phish_model.pkl'
    
    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"❌ ERROR: Dataset not found at: {dataset_path}")
        print("\n📥 REQUIRED STEPS:")
        print("-" * 70)
        print("1. Download dataset from:")
        print("   https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
        print("\n2. Prepare the dataset:")
        print("   cd ml_training")
        print("   python prepare_kaggle.py")
        print("\n3. Run this training script again:")
        print("   python train_model.py")
        print("-" * 70)
        return
    
    # Check file size to ensure it's a real dataset
    file_size_mb = os.path.getsize(dataset_path) / (1024 * 1024)
    print(f"Dataset file size: {file_size_mb:.2f} MB")
    
    if file_size_mb < 1:
        print("\n⚠️  WARNING: Dataset appears very small!")
        print("   Expected size: 5-15 MB for Kaggle dataset")
        print("   Current size:", f"{file_size_mb:.2f} MB")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Training cancelled.")
            return
    
    # Load and prepare data
    X, y = load_and_prepare_data(dataset_path)
    
    if X is None or y is None:
        print("\n❌ ERROR: Failed to load dataset")
        return
    
    # Check dataset size
    if len(X) < 1000:
        print(f"\n⚠️  WARNING: Very small dataset ({len(X)} samples)")
        print("   Recommended minimum: 10,000 samples")
        print("   For best results: 50,000+ samples")
        response = input("\nContinue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Training cancelled.")
            return
    
    # Train model
    model, feature_importance = train_model(X, y)
    
    # Save model
    print("\n" + "=" * 70)
    print("SAVING MODEL")
    print("=" * 70 + "\n")
    save_model(model, feature_importance, model_output_path)
    
    print("\n" + "=" * 70)
    print("✅ TRAINING COMPLETE!")
    print("=" * 70)
    print("\nYour phishing detection model is ready to use!")
    print("\n📋 NEXT STEPS:")
    print("-" * 70)
    print("1. Start the backend server:")
    print("   cd backend")
    print("   python -m app.main")
    print("   # OR")
    print("   cd ..")
    print("   uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000")
    print("\n2. Reload the Chrome extension:")
    print("   - Go to chrome://extensions/")
    print("   - Click the refresh icon on Phish-Shield")
    print("\n3. Test the system:")
    print("   - Visit https://www.google.com (should show LOW risk)")
    print("   - Visit suspicious URLs (should show HIGH risk)")
    print("\n4. Monitor performance:")
    print("   - Check browser console for scan results")
    print("   - Click extension icon for detailed reports")
    print("-" * 70)
    print("\n🛡️  Stay safe online!")
    print()

if __name__ == "__main__":
    main()
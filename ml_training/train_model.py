import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import os

def load_structured_data(csv_path):
    print(f"🚀 Loading Enhanced 2026 Dataset from {csv_path}...")
    df = pd.read_csv(csv_path)

    # 1. HANDLE THE TARGET (y)
    # Identify the target column name in your specific CSV
    target_col = 'status' if 'status' in df.columns else 'label'
    
    if target_col not in df.columns:
        raise ValueError(f"Could not find target column '{target_col}' in CSV!")

    le = LabelEncoder()
    y = le.fit_transform(df[target_col])
    print(f"Classes encoded: {list(le.classes_)} -> {np.unique(y)}")

    # 2. HANDLE THE FEATURES (X)
    # This line is the magic fix: it ONLY keeps numeric columns (int and float)
    # This automatically ignores 'url', 'status', 'label', etc.
    X = df.select_dtypes(include=[np.number])
    
    # Optional: If you have an 'index' or 'id' column that is numeric but useless
    cols_to_ignore = ['id', 'index', 'Unnamed: 0']
    X = X.drop(columns=[c for c in cols_to_ignore if c in X.columns])

    print(f"Training on {X.shape[1]} numeric features.")
    return X, y, le

def train_phish_model(X, y):
    # Stratify ensures the 20/80 split has an equal % of phishing in both
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest (150 trees)...")
    model = RandomForestClassifier(
        n_estimators=150, 
        max_depth=25, 
        n_jobs=-1, 
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"\n✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nReport:\n", classification_report(y_test, y_pred))
    
    return model

def main():
    # Ensure this path is correct for your local machine
    dataset_path = 'datasets/final_dataset_with_all_features_v3.1.csv' 
    
    if os.path.exists(dataset_path):
        X, y, le = load_structured_data(dataset_path)
        model = train_phish_model(X, y)
        
        # Save artifacts for the backend
        os.makedirs('backend/models/', exist_ok=True)
        joblib.dump(model, 'backend/models/phish_model.pkl')
        joblib.dump(le, 'backend/models/label_encoder.pkl')
        joblib.dump(list(X.columns), 'backend/models/feature_names.pkl')
        print("\n✓ Model and feature names saved.")
    else:
        print(f"❌ File not found at {dataset_path}")

if __name__ == "__main__":
    main()
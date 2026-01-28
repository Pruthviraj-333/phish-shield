"""
Prepare Kaggle Phishing Dataset
Works with multiple Kaggle dataset formats
"""

import pandas as pd
import os

def prepare_kaggle_dataset():
    """Prepare Kaggle dataset for training"""
    
    print("=" * 70)
    print("PREPARING KAGGLE PHISHING DATASET")
    print("=" * 70)
    
    # Look for downloaded Kaggle files
    possible_files = [
        "ml_training/datasets/dataset_full.csv",
        "ml_training/datasets/phishing_site_urls.csv",
        "ml_training/datasets/phishing.csv",
        "ml_training/datasets/dataset_phishing.csv",
        "ml_training/datasets/web-page-phishing.csv",
    ]
    
    dataset_path = None
    for path in possible_files:
        if os.path.exists(path):
            dataset_path = path
            break
    
    if dataset_path is None:
        print("❌ Kaggle dataset not found!")
        print("\n📥 DOWNLOAD INSTRUCTIONS:")
        print("-" * 70)
        print("1. Visit one of these Kaggle datasets:")
        print("   Option A (Recommended - 88K URLs):")
        print("   https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
        print("\n   Option B (Quick - 11K URLs):")
        print("   https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls")
        print("\n2. Create free Kaggle account if needed")
        print("3. Click 'Download' button")
        print("4. Extract the ZIP file")
        print("5. Move CSV to: ml_training/datasets/")
        print("6. Run this script again")
        print("-" * 70)
        
        # Check for any CSV in datasets folder
        dataset_dir = "datasets"
        if os.path.exists(dataset_dir):
            csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv')]
            if csv_files:
                print(f"\nFound these CSV files in {dataset_dir}:")
                for i, f in enumerate(csv_files, 1):
                    file_path = os.path.join(dataset_dir, f)
                    file_size = os.path.getsize(file_path) / (1024 * 1024)
                    print(f"  {i}. {f} ({file_size:.2f} MB)")
                
                choice = input("\nEnter number to use this file (or Enter to exit): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(csv_files):
                    dataset_path = os.path.join(dataset_dir, csv_files[int(choice) - 1])
                else:
                    return False
            else:
                return False
        else:
            os.makedirs(dataset_dir, exist_ok=True)
            return False
    
    if dataset_path is None:
        return False
    
    print(f"\n✓ Found dataset at: {dataset_path}\n")
    
    # Load dataset
    print("Loading dataset...")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return False
    
    print(f"✓ Loaded {len(df):,} rows")
    print(f"✓ Columns: {list(df.columns)}\n")
    
    # Show sample
    print("Sample of data:")
    print(df.head())
    print()
    
    # Detect columns
    url_col = None
    label_col = None
    
    # Common URL column names
    url_keywords = ['url', 'urls', 'link', 'website', 'domain', 'site', 'address']
    for col in df.columns:
        if any(keyword in col.lower() for keyword in url_keywords):
            url_col = col
            break
    
    # Common label column names
    label_keywords = ['label', 'class', 'type', 'status', 'target', 'category', 'result']
    for col in df.columns:
        if any(keyword in col.lower() for keyword in label_keywords):
            label_col = col
            break
    
    # Manual input if not found
    if url_col is None or label_col is None:
        print("Could not auto-detect columns.")
        print(f"Available columns: {list(df.columns)}")
        
        if url_col is None:
            url_col = input("Enter URL column name: ").strip()
        if label_col is None:
            label_col = input("Enter label column name: ").strip()
    
    print(f"\n✓ Using columns:")
    print(f"  URL column: '{url_col}'")
    print(f"  Label column: '{label_col}'\n")
    
    # Create clean dataframe
    try:
        clean_df = pd.DataFrame({
            'url': df[url_col],
            'label': df[label_col]
        })
    except KeyError as e:
        print(f"❌ Error: {e}")
        return False
    
    # Clean data
    print("Cleaning data...")
    original_size = len(clean_df)
    
    # Remove NaN
    clean_df = clean_df.dropna()
    
    # Check label format
    unique_labels = clean_df['label'].unique()
    print(f"Unique labels found: {unique_labels}")
    
    # Convert labels to 0/1
    if clean_df['label'].dtype == 'object':
        # Map text labels
        label_map = {}
        
        # Common mappings
        common_maps = {
            'legitimate': 0, 'legit': 0, 'good': 0, 'safe': 0, 'benign': 0, 'normal': 0,
            'phishing': 1, 'phish': 1, 'bad': 1, 'malicious': 1, 'fraud': 1, 'suspicious': 1,
            '0': 0, '1': 1, 'false': 0, 'true': 1, 'no': 0, 'yes': 1
        }
        
        clean_df['label'] = clean_df['label'].astype(str).str.lower().str.strip()
        clean_df['label'] = clean_df['label'].map(common_maps)
    
    # Convert to numeric
    clean_df['label'] = pd.to_numeric(clean_df['label'], errors='coerce')
    
    # Remove invalid labels
    clean_df = clean_df.dropna(subset=['label'])
    clean_df['label'] = clean_df['label'].astype(int)
    clean_df = clean_df[clean_df['label'].isin([0, 1])]
    
    # Remove duplicates
    clean_df = clean_df.drop_duplicates(subset=['url'])
    
    print(f"✓ Removed {original_size - len(clean_df):,} invalid/duplicate rows")
    print(f"✓ Final dataset: {len(clean_df):,} URLs\n")
    
    # Show distribution
    print("=" * 70)
    print("CLASS DISTRIBUTION")
    print("=" * 70)
    
    counts = clean_df['label'].value_counts().sort_index()
    print(f"\nLegitimate (0): {counts[0]:>8,} URLs ({counts[0]/len(clean_df)*100:.2f}%)")
    print(f"Phishing (1):   {counts[1]:>8,} URLs ({counts[1]/len(clean_df)*100:.2f}%)")
    print(f"Total:          {len(clean_df):>8,} URLs")
    
    # Balance check
    balance_ratio = min(counts[0], counts[1]) / max(counts[0], counts[1])
    print(f"\nBalance ratio: {balance_ratio:.2f}")
    
    if balance_ratio > 0.8:
        print("✓ Well-balanced dataset!")
    elif balance_ratio > 0.6:
        print("⚠ Moderately balanced")
    else:
        print("⚠ Imbalanced - will use class weights during training")
    
    # Save
    output_path = "datasets/dataset_phishing.csv"
    clean_df.to_csv(output_path, index=False)
    
    print(f"\n✓ Saved to: {output_path}")
    print(f"✓ File size: {os.path.getsize(output_path) / (1024*1024):.2f} MB")
    
    # Sample
    print("\nSample URLs:")
    print("-" * 70)
    for _, row in clean_df.sample(min(10, len(clean_df))).iterrows():
        label = "PHISHING  " if row['label'] == 1 else "LEGITIMATE"
        print(f"[{label}] {row['url'][:60]}")
    
    print("\n" + "=" * 70)
    print("✅ DATASET READY!")
    print("=" * 70)
    print("\nNext: Train the model")
    print("  cd ml_training")
    print("  python train_model.py")
    
    return True

if __name__ == "__main__":
    prepare_kaggle_dataset()
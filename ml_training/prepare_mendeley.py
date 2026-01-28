"""
Mendeley Dataset Preparation Script
Converts the Mendeley Phishing Dataset into the format required for training
"""

import pandas as pd
import os

def prepare_mendeley_dataset():
    """Prepare Mendeley dataset for training"""
    
    print("=" * 70)
    print("PREPARING MENDELEY PHISHING DATASET")
    print("=" * 70)
    print("\nDataset: https://data.mendeley.com/datasets/c2gw7fy2j4/3")
    print("Size: ~248,000 URLs")
    print("Published: March 2024\n")
    
    # Look for downloaded file in common locations
    possible_paths = [
        "ml_training/datasets/phishing_dataset_raw.csv",
        "ml_training/datasets/Phishing_Legitimate_full.csv",
        "ml_training/datasets/phishing_urls.csv",
        "ml_training/datasets/mendeley_phishing.csv",
    ]
    
    download_path = None
    for path in possible_paths:
        if os.path.exists(path):
            download_path = path
            break
    
    if download_path is None:
        print("❌ Dataset not found in expected locations:")
        for path in possible_paths:
            print(f"   - {path}")
        
        print("\n📥 DOWNLOAD INSTRUCTIONS:")
        print("-" * 70)
        print("1. Visit: https://data.mendeley.com/datasets/c2gw7fy2j4/3")
        print("2. Click the 'Download' button")
        print("3. Extract the ZIP file")
        print("4. Save the CSV file to one of these locations:")
        print("   ml_training/datasets/phishing_dataset_raw.csv (recommended)")
        print("   OR just place any CSV file in ml_training/datasets/")
        print("5. Run this script again")
        print("-" * 70)
        
        # Check if there are any CSV files in the directory
        dataset_dir = "ml_training/datasets"
        if os.path.exists(dataset_dir):
            csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv')]
            if csv_files:
                print(f"\nFound these CSV files in {dataset_dir}:")
                for i, f in enumerate(csv_files, 1):
                    print(f"  {i}. {f}")
                
                choice = input("\nEnter the number of the file to use (or press Enter to exit): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(csv_files):
                    download_path = os.path.join(dataset_dir, csv_files[int(choice) - 1])
                    print(f"\n✓ Using: {download_path}")
                else:
                    return False
            else:
                return False
        else:
            os.makedirs(dataset_dir, exist_ok=True)
            return False
    
    if download_path is None:
        return False
    
    print(f"✓ Found dataset at: {download_path}\n")
    
    # Output path
    output_path = "ml_training/datasets/phishing_urls.csv"
    
    # Load dataset
    print("Loading dataset...")
    try:
        df = pd.read_csv(download_path)
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return False
    
    print(f"✓ Loaded {len(df):,} rows")
    print(f"✓ Columns: {list(df.columns)}\n")
    
    # Identify URL and label columns
    url_col = None
    label_col = None
    
    # Find URL column (case-insensitive)
    url_keywords = ['url', 'urls', 'link', 'website', 'domain', 'site']
    for col in df.columns:
        if any(keyword in col.lower() for keyword in url_keywords):
            url_col = col
            print(f"✓ Detected URL column: '{url_col}'")
            break
    
    # Find label column (case-insensitive)
    label_keywords = ['label', 'class', 'type', 'status', 'target', 'category']
    for col in df.columns:
        if any(keyword in col.lower() for keyword in label_keywords):
            label_col = col
            print(f"✓ Detected label column: '{label_col}'")
            break
    
    # Manual selection if auto-detection fails
    if url_col is None or label_col is None:
        print(f"\n⚠️  Could not auto-detect all required columns")
        print(f"Available columns: {list(df.columns)}")
        print("\nColumn preview:")
        print(df.head())
        print("\nPlease specify manually:")
        
        if url_col is None:
            url_col = input("Enter URL column name: ").strip()
        if label_col is None:
            label_col = input("Enter label column name: ").strip()
    
    print(f"\nUsing columns:")
    print(f"  URL: '{url_col}'")
    print(f"  Label: '{label_col}'\n")
    
    # Create clean dataframe
    try:
        clean_df = pd.DataFrame({
            'url': df[url_col],
            'label': df[label_col]
        })
    except KeyError as e:
        print(f"❌ Error: Column not found - {e}")
        print(f"Available columns: {list(df.columns)}")
        return False
    
    # Show sample before cleaning
    print("Sample of original data:")
    print(clean_df.head(10))
    print()
    
    # Clean data
    print("Cleaning data...")
    original_size = len(clean_df)
    
    # Remove missing values
    clean_df = clean_df.dropna()
    print(f"✓ Removed {original_size - len(clean_df):,} rows with missing values")
    
    # Ensure label is 0 or 1
    print("\nProcessing labels...")
    print(f"Original label type: {clean_df['label'].dtype}")
    print(f"Unique values: {clean_df['label'].unique()[:10]}")  # Show first 10
    
    # Convert any text labels to numeric
    if clean_df['label'].dtype == 'object' or clean_df['label'].dtype == 'str':
        print("Converting text labels to numeric...")
        
        # Map common label formats (case-insensitive)
        label_map = {
            'legitimate': 0, 'legit': 0, 'good': 0, 'safe': 0, 'benign': 0,
            'phishing': 1, 'phish': 1, 'bad': 1, 'malicious': 1, 'fraud': 1,
            '0': 0, '1': 1, 'normal': 0, 'abnormal': 1
        }
        
        clean_df['label'] = clean_df['label'].astype(str).str.lower().str.strip()
        clean_df['label'] = clean_df['label'].map(label_map)
    
    # Convert to int
    clean_df['label'] = pd.to_numeric(clean_df['label'], errors='coerce')
    
    # Remove any rows where label couldn't be converted
    before_filter = len(clean_df)
    clean_df = clean_df.dropna(subset=['label'])
    clean_df['label'] = clean_df['label'].astype(int)
    
    # Keep only 0 and 1 labels
    clean_df = clean_df[clean_df['label'].isin([0, 1])]
    
    removed = before_filter - len(clean_df)
    if removed > 0:
        print(f"✓ Removed {removed:,} rows with invalid labels")
    
    # Remove duplicate URLs
    before_dedup = len(clean_df)
    clean_df = clean_df.drop_duplicates(subset=['url'])
    removed_dupes = before_dedup - len(clean_df)
    if removed_dupes > 0:
        print(f"✓ Removed {removed_dupes:,} duplicate URLs")
    
    print(f"\n✓ Final dataset: {len(clean_df):,} URLs")
    print(f"✓ Removed total: {original_size - len(clean_df):,} rows")
    
    # Show distribution
    print("\n" + "=" * 70)
    print("CLASS DISTRIBUTION")
    print("=" * 70)
    
    counts = clean_df['label'].value_counts().sort_index()
    print(f"\nLegitimate (0): {counts[0]:>8,} URLs ({counts[0]/len(clean_df)*100:.2f}%)")
    print(f"Phishing (1):   {counts[1]:>8,} URLs ({counts[1]/len(clean_df)*100:.2f}%)")
    print(f"Total:          {len(clean_df):>8,} URLs")
    
    # Check balance
    balance_ratio = min(counts[0], counts[1]) / max(counts[0], counts[1])
    print(f"\nBalance ratio: {balance_ratio:.2f} (closer to 1.0 is better)")
    if balance_ratio > 0.8:
        print("✓ Well-balanced dataset!")
    elif balance_ratio > 0.6:
        print("⚠ Moderately balanced dataset")
    else:
        print("⚠ Imbalanced dataset - consider using class weights")
    
    # Save cleaned dataset
    print("\n" + "=" * 70)
    print("SAVING DATASET")
    print("=" * 70)
    
    clean_df.to_csv(output_path, index=False)
    print(f"\n✓ Saved to: {output_path}")
    
    # Verify saved file
    file_size = os.path.getsize(output_path) / (1024 * 1024)  # MB
    print(f"✓ File size: {file_size:.2f} MB")
    
    # Show final sample
    print("\nSample of cleaned data:")
    print("-" * 70)
    sample = clean_df.sample(min(10, len(clean_df)))
    for idx, row in sample.iterrows():
        label_text = "PHISHING  " if row['label'] == 1 else "LEGITIMATE"
        print(f"[{label_text}] {row['url'][:60]}")
    print()
    
    print("=" * 70)
    print("✅ DATASET PREPARATION COMPLETE!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Train the model:")
    print("   cd ml_training")
    print("   python train_model.py")
    print("\n2. Expected accuracy with this dataset: 93-97%")
    print("\n3. Training time: 5-10 minutes (depending on your CPU)")
    
    return True

def main():
    """Main function"""
    success = prepare_mendeley_dataset()
    
    if success:
        print("\n🎉 Ready to train your phishing detection model!")
    else:
        print("\n❌ Dataset preparation failed. Please follow the download instructions above.")

if __name__ == "__main__":
    main()
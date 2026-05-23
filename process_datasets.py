import os
import pandas as pd
import numpy as np

DATASETS_DIR = r"C:\Users\Lenovo\Downloads\ILA-SOC-Server\ILA-SOC-Server\phish_datasets_29_april"
EXISTING_DATASET = r"C:\Users\Lenovo\Downloads\ILA-SOC-Server\ILA-SOC-Server\datasets\enhanced_training_dataset.csv"
OUTPUT_DATASET = r"C:\Users\Lenovo\Downloads\ILA-SOC-Server\ILA-SOC-Server\datasets\enhanced_training_dataset_v2.csv"

def extract_urls_and_label(file_path, filename):
    filename_lower = filename.lower()
    
    # Labeling logic
    if 'phishtank' in filename_lower or 'verified' in filename_lower:
        label = 'Malicious'
    elif 'urlhaus' in filename_lower or 'csv.txt' in filename_lower:
        label = 'Malicious'
    elif 'kaggle' in filename_lower or 'phish' in filename_lower:
        label = 'Malicious'
    elif 'legit' in filename_lower or 'tranco' in filename_lower:
        label = 'Normal'
    else:
        label = 'Suspicious'
        
    print(f"Processing {filename} with label {label}")
    
    urls = pd.Series(dtype=str)
    
    if filename.endswith('.csv') or filename.endswith('.txt'):
        if 'csv.txt' in filename_lower:
            df = pd.read_csv(file_path, comment='#', header=None, on_bad_lines='skip')
            if len(df.columns) >= 3:
                urls = df.iloc[:, 2]
        elif 'tranco' in filename_lower:
            df = pd.read_csv(file_path, header=None, on_bad_lines='skip')
            if len(df.columns) >= 2:
                urls = df.iloc[:, 1]
        else:
            try:
                df = pd.read_csv(file_path, on_bad_lines='skip')
            except Exception as e:
                print(f"Error reading {filename}: {e}")
                return pd.DataFrame()
            
            url_col = None
            for col in ['url', 'URL', 'link', 'domain']:
                if col in df.columns:
                    url_col = col
                    break
            
            if url_col:
                urls = df[url_col]
            else:
                print(f"No URL column found in {filename}")
                return pd.DataFrame()
                
    elif filename.endswith('.json'):
        df = pd.read_json(file_path)
        url_col = None
        for col in ['url', 'URL', 'link', 'domain']:
            if col in df.columns:
                url_col = col
                break
        if url_col:
            urls = df[url_col]
            
    # Cleaning
    urls = urls.dropna().astype(str).str.strip().str.lower()
    urls = urls[urls != '']
    urls = urls.drop_duplicates()
    
    return pd.DataFrame({'log_text': urls, 'label': label})


def main():
    print("--- TASK 1 & 2: Loading and normalizing datasets ---")
    new_data_frames = []
    for f in os.listdir(DATASETS_DIR):
        file_path = os.path.join(DATASETS_DIR, f)
        if os.path.isfile(file_path):
            df = extract_urls_and_label(file_path, f)
            if not df.empty:
                new_data_frames.append(df)
                print(f"Added {len(df)} URLs from {f}")

    if not new_data_frames:
        print("No new data found.")
        return

    new_data = pd.concat(new_data_frames, ignore_index=True)
    new_data = new_data.drop_duplicates(subset=['log_text'])
    print(f"Total new unique URLs: {len(new_data)}")
    
    print("\n--- TASK 3: Merging with existing dataset ---")
    existing_df = pd.read_csv(EXISTING_DATASET)
    print(f"Existing dataset size: {len(existing_df)}")
    
    merged_df = pd.concat([existing_df, new_data], ignore_index=True)
    merged_df = merged_df.drop_duplicates(subset=['log_text'])
    
    print(f"Size after merge and deduplication: {len(merged_df)}")
    
    # Class balancing
    # Targets: Malicious 60K, Normal 45K, Suspicious 15K
    targets = {
        'Malicious': 60000,
        'Normal': 45000,
        'Suspicious': 15000
    }
    
    balanced_dfs = []
    for label, target_count in targets.items():
        subset = merged_df[merged_df['label'] == label]
        current_count = len(subset)
        print(f"{label} count before balance: {current_count}")
        
        if current_count > target_count:
            subset = subset.sample(n=target_count, random_state=42)
        elif current_count < target_count:
            # If we don't have enough, we'll upsample (with replacement) to hit the exact target
            # or just take what we have. The prompt says "Maintain class balance... ≈ 60K"
            # It's usually better to just take what we have or slightly upsample.
            # Let's upsample to hit the exact target so it balances perfectly
            diff = target_count - current_count
            upsample = subset.sample(n=diff, replace=True, random_state=42)
            subset = pd.concat([subset, upsample], ignore_index=True)
            
        balanced_dfs.append(subset)
        
    final_df = pd.concat(balanced_dfs, ignore_index=True)
    # Shuffle
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    final_df.to_csv(OUTPUT_DATASET, index=False)
    
    print(f"\nFinal dataset saved to {OUTPUT_DATASET}")
    print("Final class distribution:")
    print(final_df['label'].value_counts())
    print(f"Total size: {len(final_df)}")

if __name__ == '__main__':
    main()

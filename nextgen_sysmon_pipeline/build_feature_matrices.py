import os
import json
import csv
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Any

from nextgen_sysmon_pipeline.feature_extractor import SysmonFeatureExtractor
from nextgen_sysmon_pipeline.process_tracker import ProcessTracker

# Standard feature vector keys to ensure consistent dimension
FEATURE_KEYS = [
    # Base Features
    'is_system_user', 'is_admin_user', 'is_lolbin', 'suspicious_process_path', 'process_depth',
    # Event ID 1
    'suspicious_parent_child', 'office_child_process', 'script_interpreter_spawn', 
    'unsigned_temp_execution', 'powershell_encoded', 'commandline_entropy',
    # Event ID 3
    'suspicious_port', 'external_network_connection', 'non_standard_external_port',
    # Event ID 10
    'lsass_access', 'suspicious_access_right',
    # Event ID 12/13/14
    'registry_persistence', 'registry_security_downgrade',
    # Event ID 22
    'dns_entropy', 'dns_dga_likely',
    # Event ID 17/18
    'named_pipe_usage', 'suspicious_named_pipe'
]

def build_feature_matrices(input_files: List[str], output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    tracker = ProcessTracker()
    extractor = SysmonFeatureExtractor(tracker)
    
    all_features = []
    all_labels = []
    metadata = {
        'total_events': 0,
        'feature_names': FEATURE_KEYS,
        'event_id_distribution': {},
        'class_distribution': {}
    }
    
    print(f"Building feature matrices from {len(input_files)} datasets...")
    
    for filepath in input_files:
        print(f"Processing {filepath}...")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        event = json.loads(line)
                        label = event.get('label', 'Unknown')
                        eid = str(event.get('event_id', 'Unknown'))
                        
                        # Extract variable length features
                        feat_dict = extractor.extract_features(event)
                        
                        # Normalize to fixed vector
                        fixed_vector = []
                        for key in FEATURE_KEYS:
                            fixed_vector.append(feat_dict.get(key, 0.0))
                            
                        all_features.append(fixed_vector)
                        all_labels.append(label)
                        
                        metadata['total_events'] += 1
                        metadata['event_id_distribution'][eid] = metadata['event_id_distribution'].get(eid, 0) + 1
                        metadata['class_distribution'][label] = metadata['class_distribution'].get(label, 0) + 1
                        
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            print(f"Warning: File {filepath} not found.")

    print(f"Extracted {metadata['total_events']} feature vectors.")
    
    # Save Feature Matrix (X)
    X_path = os.path.join(output_dir, 'X_structured.csv')
    df_x = pd.DataFrame(all_features, columns=FEATURE_KEYS)
    df_x.to_csv(X_path, index=False)
    print(f"Saved X_structured.csv ({len(df_x)} rows)")
    
    # Save Numpy Array for speed
    np.save(os.path.join(output_dir, 'X_structured.npy'), df_x.to_numpy())
    
    # Save Labels (y)
    y_path = os.path.join(output_dir, 'y_labels.csv')
    df_y = pd.DataFrame({'label': all_labels})
    df_y.to_csv(y_path, index=False)
    print(f"Saved y_labels.csv ({len(df_y)} rows)")
    
    np.save(os.path.join(output_dir, 'y_labels.npy'), df_y['label'].to_numpy())
    
    # Save Metadata
    meta_path = os.path.join(output_dir, 'feature_metadata.json')
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    print("Saved feature_metadata.json")

if __name__ == '__main__':
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / 'sysmon_parser' / 'output'
    out_dir = project_root / 'nextgen_sysmon_pipeline' / 'training_data'
    
    inputs = [
        str(data_dir / 'synthetic_benign_sysmon.json'),
        str(data_dir / 'synthetic_balanced_sysmon.json')
    ]
    
    build_feature_matrices(inputs, str(out_dir))

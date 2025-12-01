#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pandas as pd
import numpy as np
import time
import warnings
import sys
from pathlib import Path
from sklearn.feature_selection import mutual_info_classif
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt

warnings.filterwarnings('ignore')


class ProgressBar:
    def __init__(self, total, prefix='Progress', length=50):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.start_time = time.time()
    
    def update(self, current):
        percent = 100 * (current / float(self.total))
        filled = int(self.length * current // self.total)
        bar = '█' * filled + '-' * (self.length - filled)
        
        elapsed = time.time() - self.start_time
        if current > 0:
            eta = elapsed * (self.total - current) / current
            eta_str = f"ETA: {eta:.0f}s"
        else:
            eta_str = "ETA: --"
        
        sys.stdout.write(f'\r{self.prefix} |{bar}| {percent:.1f}% ({current}/{self.total}) {eta_str}')
        sys.stdout.flush()
    
    def finish(self):
        sys.stdout.write('\n')
        sys.stdout.flush()


CONFIG = {
    'sample_ratio': 0.1,
    'variance_threshold': 0.01,
    'top_k_features': 30,
    'random_state': 42,
    'use_big_dataset': True,
}

BIG_DATA_FILES = [
    'UNSW-NB15_1.csv',
    'UNSW-NB15_2.csv', 
    'UNSW-NB15_3.csv',
    'UNSW-NB15_4.csv'
]

COLUMN_NAMES = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 
    'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'service',
    'sload', 'dload', 'spkts', 'dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
    'smean', 'dmean', 'trans_depth', 'response_body_len', 'sjit', 'djit',
    'Stime', 'Ltime', 'sinpkt', 'dinpkt', 'tcprtt', 'synack', 'ackdat',
    'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
]

USELESS_FEATURES = ['srcip', 'sport', 'dstip', 'dsport', 'Stime', 'Ltime', 'attack_cat']
CATEGORICAL_FEATURES = ['proto', 'service', 'state']
BINARY_FEATURES = ['is_ftp_login', 'is_sm_ips_ports']


def print_section(title):
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)


def log_time(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"Time elapsed: {elapsed:.2f}s")
        return result
    return wrapper


@log_time
def load_data():
    print_section("Phase 0: Data Loading")
    
    print(f"Loading big dataset with {CONFIG['sample_ratio']*100:.0f}% sampling")
    
    dfs = []
    total_files = len(BIG_DATA_FILES)
    
    for idx, file in enumerate(BIG_DATA_FILES, 1):
        if not Path(file).exists():
            print(f"[{idx}/{total_files}] File not found: {file}")
            continue
        
        print(f"[{idx}/{total_files}] Loading {file}...")
        
        df = pd.read_csv(file, header=None, names=COLUMN_NAMES, low_memory=False)
        
        if CONFIG['sample_ratio'] < 1.0:
            n_samples = int(len(df) * CONFIG['sample_ratio'])
            df = df.sample(n=n_samples, random_state=CONFIG['random_state'] + idx)
            print(f"  Sampled {len(df):,} records")
        else:
            print(f"  Loaded {len(df):,} records")
        
        dfs.append(df)
    
    if not dfs:
        raise FileNotFoundError("No data files found")
    
    print("\nMerging all data...")
    df_full = pd.concat(dfs, ignore_index=True)
    
    df_full.columns = df_full.columns.str.lower()
    
    print("\nCleaning data...")
    df_full.replace(r'^\s*$', np.nan, regex=True, inplace=True)
    
    object_cols = [col for col in df_full.columns 
                   if df_full[col].dtype == 'object' and col not in ['proto', 'service', 'state', 'attack_cat']]
    
    for col in object_cols:
        df_full[col] = pd.to_numeric(df_full[col], errors='coerce')
    
    missing_counts = df_full.isnull().sum()
    missing_total = missing_counts.sum()
    if missing_total > 0:
        print(f"Missing values: {missing_total:,} ({missing_total / (len(df_full) * len(df_full.columns)) * 100:.2f}%)")
    
    print(f"\nData loaded:")
    print(f"  Total records: {len(df_full):,}")
    print(f"  Total features: {len(df_full.columns)}")
    print(f"  Memory usage: {df_full.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
    
    if 'label' in df_full.columns:
        label_dist = df_full['label'].value_counts().sort_index()
        print(f"\nLabel distribution:")
        for label, count in label_dist.items():
            pct = count / len(df_full) * 100
            label_name = "Normal" if label == 0 else "Attack"
            print(f"  {label_name} ({label}): {count:>10,} ({pct:>5.2f}%)")
    
    return df_full


def phase1_remove_useless(df):
    print_section("Phase 1: Remove Useless Features")
    
    removed = []
    useless_lower = [f.lower() for f in USELESS_FEATURES]
    
    for feat in useless_lower:
        if feat in df.columns:
            df = df.drop(columns=[feat])
            removed.append(feat)
            print(f"  Removed: {feat}")
    
    print(f"\nPhase 1 completed:")
    print(f"  Removed: {len(removed)} features")
    print(f"  Remaining: {len(df.columns) - 1} features")
    
    return df, removed


@log_time
def phase2_variance_filter(df, threshold=0.01):
    print_section("Phase 2: Variance Filter")
    
    if 'label' not in df.columns:
        raise ValueError("Label column not found")
    
    y = df['label']
    X = df.drop(columns=['label'])
    
    X_processed = X.copy()
    categorical_lower = [f.lower() for f in CATEGORICAL_FEATURES]
    
    for col in categorical_lower:
        if col in X_processed.columns:
            le = LabelEncoder()
            X_processed[col] = le.fit_transform(X_processed[col].astype(str))
    
    for col in X_processed.columns:
        if X_processed[col].dtype == 'object':
            X_processed[col] = pd.to_numeric(X_processed[col], errors='coerce')
    
    X_processed = X_processed.fillna(X_processed.median())
    
    variances = X_processed.var(numeric_only=True)
    variances_sorted = variances.sort_values(ascending=True)
    
    print(f"\nVariance statistics:")
    print(f"  Min: {variances.min():.6f}")
    print(f"  Max: {variances.max():.6f}")
    print(f"  Median: {variances.median():.6f}")
    
    print(f"\nLowest 10 variance features:")
    for feat, var in variances_sorted.head(10).items():
        print(f"  {feat:<25} : {var:.6f}")
    
    low_variance_features = variances[variances < threshold].index.tolist()
    
    binary_lower = [f.lower() for f in BINARY_FEATURES]
    protected_features = []
    for feat in binary_lower:
        if feat in low_variance_features:
            low_variance_features.remove(feat)
            protected_features.append(feat)
    
    if protected_features:
        print(f"\nProtected binary features:")
        for feat in protected_features:
            print(f"  {feat} (variance: {variances[feat]:.6f})")
    
    X_filtered = X.drop(columns=low_variance_features)
    
    print(f"\nPhase 2 completed:")
    print(f"  Removed: {len(low_variance_features)} features")
    print(f"  Remaining: {len(X_filtered.columns)} features")
    
    if low_variance_features:
        print(f"\nRemoved features:")
        for feat in low_variance_features:
            print(f"  {feat} (variance: {variances[feat]:.6f})")
    
    return X_filtered, y, low_variance_features, variances


@log_time
def phase3_mutual_information(X, y, top_k=30):
    print_section("Phase 3: Mutual Information Selection")
    
    X_processed = X.copy()
    categorical_mask = []
    categorical_lower = [f.lower() for f in CATEGORICAL_FEATURES]
    
    for col in X.columns:
        if col in categorical_lower:
            le = LabelEncoder()
            X_processed[col] = le.fit_transform(X_processed[col].astype(str))
            categorical_mask.append(True)
        else:
            categorical_mask.append(False)
    
    X_processed = X_processed.fillna(X_processed.median())
    
    print(f"\nCalculating mutual information scores...")
    print(f"  Features: {X_processed.shape[1]}")
    print(f"  Samples: {X_processed.shape[0]:,}")
    print(f"  This may take a few minutes...")
    
    start_time = time.time()
    
    mi_scores = mutual_info_classif(
        X_processed, 
        y, 
        discrete_features=categorical_mask,
        random_state=CONFIG['random_state'],
        n_neighbors=3
    )
    
    elapsed = time.time() - start_time
    print(f"  Completed in {elapsed:.1f}s")
    
    mi_df = pd.DataFrame({
        'feature': X.columns,
        'mi_score': mi_scores,
        'is_categorical': categorical_mask
    }).sort_values('mi_score', ascending=False)
    
    print(f"\nMutual information statistics:")
    print(f"  Max: {mi_scores.max():.6f}")
    print(f"  Min: {mi_scores.min():.6f}")
    print(f"  Mean: {mi_scores.mean():.6f}")
    print(f"  Median: {np.median(mi_scores):.6f}")
    
    print(f"\nTop 15 features:")
    for idx, row in mi_df.head(15).iterrows():
        feat_type = "categorical" if row['is_categorical'] else "numerical"
        print(f"  {row['feature']:<25} : {row['mi_score']:.6f} ({feat_type})")
    
    print(f"\nBottom 10 features:")
    for idx, row in mi_df.tail(10).iterrows():
        feat_type = "categorical" if row['is_categorical'] else "numerical"
        print(f"  {row['feature']:<25} : {row['mi_score']:.6f} ({feat_type})")
    
    selected_features = mi_df.head(top_k)['feature'].tolist()
    
    print(f"\nPhase 3 completed:")
    print(f"  Selected: {len(selected_features)} features")
    print(f"  Cumulative MI: {mi_df.head(top_k)['mi_score'].sum():.4f}")
    print(f"  Coverage: {mi_df.head(top_k)['mi_score'].sum() / mi_df['mi_score'].sum() * 100:.2f}%")
    
    return selected_features, mi_df


def phase4_output_results(removed_features, low_var_features, variances, mi_df, selected_features):
    print_section("Phase 4: Output Results")
    
    output_dir = Path("feature_selection_results")
    
    if output_dir.exists():
        print(f"Clearing old results...")
        for file in output_dir.glob("*"):
            if file.is_file():
                file.unlink()
    else:
        output_dir.mkdir(exist_ok=True)
    
    with open(output_dir / "01_removed_features.txt", 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("Removed Features\n")
        f.write("="*80 + "\n\n")
        
        f.write("Phase 1: Useless features\n")
        for feat in removed_features:
            f.write(f"  - {feat}\n")
        
        f.write(f"\nPhase 2: Low variance features (threshold < {CONFIG['variance_threshold']})\n")
        for feat in low_var_features:
            var_value = variances[feat] if feat in variances else 0
            f.write(f"  - {feat:<30} (variance: {var_value:.6f})\n")
        
        f.write(f"\nTotal removed: {len(removed_features) + len(low_var_features)}\n")
    
    print(f"  Saved: 01_removed_features.txt")
    
    var_df = pd.DataFrame({
        'feature': variances.index,
        'variance': variances.values
    }).sort_values('variance', ascending=False)
    var_df.to_csv(output_dir / "02_variance_scores.csv", index=False)
    print(f"  Saved: 02_variance_scores.csv")
    
    mi_df.to_csv(output_dir / "03_mutual_info_scores.csv", index=False)
    print(f"  Saved: 03_mutual_info_scores.csv")
    
    with open(output_dir / "04_selected_features.txt", 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write(f"Selected {len(selected_features)} Features\n")
        f.write("="*80 + "\n\n")
        
        for i, feat in enumerate(selected_features, 1):
            mi_score = mi_df[mi_df['feature'] == feat]['mi_score'].values[0]
            f.write(f"{i:2d}. {feat:<30} (MI: {mi_score:.6f})\n")
        
        f.write("\n" + "-"*80 + "\n")
        f.write("Python list format:\n")
        f.write("SELECTED_FEATURES = [\n")
        for feat in selected_features:
            f.write(f"    '{feat}',\n")
        f.write("]\n")
    
    print(f"  Saved: 04_selected_features.txt")
    
    with open(output_dir / "05_feature_selection_report.txt", 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("UNSW-NB15 Feature Selection Report\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Configuration:\n")
        f.write(f"  - Sample ratio: {CONFIG['sample_ratio']*100:.0f}%\n")
        f.write(f"  - Variance threshold: {CONFIG['variance_threshold']}\n")
        f.write(f"  - Top K features: {CONFIG['top_k_features']}\n")
        f.write(f"  - Random seed: {CONFIG['random_state']}\n\n")
        
        f.write(f"Feature selection pipeline:\n")
        f.write(f"  Phase 1: Remove useless ({len(removed_features)} features)\n")
        f.write(f"  Phase 2: Variance filter ({len(low_var_features)} features)\n")
        f.write(f"  Phase 3: Mutual information (select {len(selected_features)} features)\n\n")
        
        f.write(f"Feature type statistics:\n")
        categorical_lower = [x.lower() for x in CATEGORICAL_FEATURES]
        binary_lower = [x.lower() for x in BINARY_FEATURES]
        cat_count = sum(1 for f in selected_features if f in categorical_lower)
        bin_count = sum(1 for f in selected_features if f in binary_lower)
        num_count = len(selected_features) - cat_count - bin_count
        f.write(f"  - Categorical: {cat_count}\n")
        f.write(f"  - Binary: {bin_count}\n")
        f.write(f"  - Numerical: {num_count}\n\n")
        
        f.write("Top 10 features:\n")
        for i, feat in enumerate(selected_features[:10], 1):
            mi_score = mi_df[mi_df['feature'] == feat]['mi_score'].values[0]
            feat_type = "categorical" if feat in categorical_lower else "numerical"
            f.write(f"  {i:2d}. {feat:<25} MI={mi_score:.6f} ({feat_type})\n")
    
    print(f"  Saved: 05_feature_selection_report.txt")
    
    create_visualizations(mi_df, selected_features, output_dir)
    
    print(f"\nAll results saved to: {output_dir.absolute()}/")


def create_visualizations(mi_df, selected_features, output_dir):
    print(f"\nGenerating visualizations...")
    
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False
    
    fig, axes = plt.subplots(2, 1, figsize=(14, 10))
    
    top_30 = mi_df.head(30)
    colors = ['#2ecc71' if f in selected_features else '#95a5a6' for f in top_30['feature']]
    
    axes[0].barh(range(len(top_30)), top_30['mi_score'], color=colors)
    axes[0].set_yticks(range(len(top_30)))
    axes[0].set_yticklabels(top_30['feature'])
    axes[0].set_xlabel('Mutual Information Score', fontsize=12)
    axes[0].set_title('Top 30 Features - Mutual Information Scores', fontsize=14, fontweight='bold')
    axes[0].invert_yaxis()
    axes[0].grid(axis='x', alpha=0.3)
    
    cumsum = mi_df['mi_score'].cumsum() / mi_df['mi_score'].sum() * 100
    axes[1].plot(range(1, len(cumsum)+1), cumsum.values, linewidth=2, color='#3498db')
    axes[1].axhline(y=95, color='r', linestyle='--', label='95% threshold')
    axes[1].axvline(x=CONFIG['top_k_features'], color='g', linestyle='--', 
                    label=f'Selected {CONFIG["top_k_features"]} features')
    axes[1].set_xlabel('Number of Features', fontsize=12)
    axes[1].set_ylabel('Cumulative MI Contribution (%)', fontsize=12)
    axes[1].set_title('Cumulative Mutual Information Contribution', fontsize=14, fontweight='bold')
    axes[1].legend()
    axes[1].grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_dir / "06_feature_importance_visualization.png", dpi=300, bbox_inches='tight')
    print(f"  Saved: 06_feature_importance_visualization.png")
    plt.close()


def main():
    print("\n" + "="*80)
    print(" " * 15 + "UNSW-NB15 Feature Selection - Statistical Method")
    print(" " * 15 + f"Sample Ratio: {CONFIG['sample_ratio']*100:.0f}% | Top K: {CONFIG['top_k_features']}")
    print("="*80)
    
    start_time = time.time()
    
    try:
        df = load_data()
        
        df, removed_features = phase1_remove_useless(df)
        
        X, y, low_var_features, variances = phase2_variance_filter(
            df, 
            threshold=CONFIG['variance_threshold']
        )
        
        selected_features, mi_df = phase3_mutual_information(
            X, y, 
            top_k=CONFIG['top_k_features']
        )
        
        phase4_output_results(
            removed_features, 
            low_var_features, 
            variances, 
            mi_df, 
            selected_features
        )
        
        print_section("Execution Completed")
        total_time = time.time() - start_time
        print(f"\nFeature selection completed successfully")
        print(f"  Original features: 49")
        print(f"  Phase 1 removed: {len(removed_features)}")
        print(f"  Phase 2 removed: {len(low_var_features)}")
        print(f"  Final selected: {len(selected_features)}")
        print(f"  Total time: {total_time:.2f}s ({total_time/60:.2f} min)")
        print(f"\nResults saved to: feature_selection_results/")
        
    except Exception as e:
        print(f"\nExecution failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

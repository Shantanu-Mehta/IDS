# predictor.py
import pandas as pd
from collections import Counter
import joblib
import math
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Suppress the scikit-learn version mismatch warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

top_30_syscalls = ['clone', 'socket', 'execve', 'connect', 'unlinkat', 'bind', 'rename', 'unlink', 'setgroups',
                   'setresuid', 'setresgid', 'fchmod', 'capget', 'fchown', 'mount', 'vfork', 'symlink',
                   'setgid', 'setuid', 'link', 'accept', 'capset', 'symlinkat', 'chown', 'umount2',
                   'chmod', 'linkat', 'syscall', 'renameat', 'execveat']

def extract_features(csv_path):
    df = pd.read_csv(csv_path, skiprows=0)  # ✅ To include header, change to skiprows=1 to skip header

    syscall_list = df['syscall'].dropna().astype(str).tolist()
    total = len(syscall_list)
    syscall_counts = Counter(syscall_list)

    features = {f'freq_{sc}': syscall_counts.get(sc, 0) / total if total else 0 for sc in top_30_syscalls}
    features['unique_syscalls'] = len(set(syscall_list))
    p = pd.Series(list(syscall_counts.values())) / total if total else pd.Series([0])
    features['entropy'] = -sum(p * p.apply(lambda x: 0 if x == 0 else math.log2(x)))
    return pd.DataFrame([features])

def load_model(path):
    return joblib.load(path)

def predict_attacks(model, feature_columns, csv_path):
    features_df = extract_features(csv_path)
    for col in feature_columns:
        if col not in features_df.columns:
            features_df[col] = 0.0
    features_df = features_df[feature_columns]
    pred = model.predict(features_df)[0]
    return "🚨 ATTACK" if pred == 1 else "✅ NORMAL"


"""Training pipeline for the malicious URL / phishing detector.

Loads data/malicious_phish.csv, converts the multi-class "type" column into a
binary label (benign -> 0, defacement/phishing/malware -> 1), turns each URL
string into a numeric feature vector using features.py, trains a
RandomForestClassifier and caches the fitted model plus its real measured
metrics to model_cache/model.joblib.

No network access is performed anywhere in this project - URLs are treated as
plain strings and are never fetched or opened.

Run directly to train and print the metrics:

    python train.py
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, featurize

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "malicious_phish.csv"
MODEL_DIR = BASE_DIR / "model_cache"
MODEL_PATH = MODEL_DIR / "model.joblib"

# Number of rows used for training. The full dataset is 651,191 rows; we take a
# stratified random sample purely for speed so the whole pipeline finishes in a
# reasonable time on a laptop. Set SAMPLE_SIZE = None to train on all 651,191
# rows - that single constant is the only change required.
SAMPLE_SIZE = 200_000

RANDOM_STATE = 42
TEST_SIZE = 0.2
N_ESTIMATORS = 200
TOP_FEATURE_COUNT = 15


def load_dataset() -> pd.DataFrame:
    """Read the CSV and attach the binary label column."""
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    frame = pd.read_csv(DATA_PATH)
    missing = {"url", "type"} - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing expected column(s): {sorted(missing)}")

    frame = frame.dropna(subset=["url", "type"])
    frame["url"] = frame["url"].astype(str)
    frame["label"] = (frame["type"] != "benign").astype(int)
    return frame


def add_bare_domain_variants(frame: pd.DataFrame, fraction: float = 0.30) -> pd.DataFrame:
    """Augment the training data with host-only copies of existing URLs.

    WHY THIS EXISTS
    ---------------
    malicious_phish.csv has a second collection artifact, as damaging as the
    scheme leak that features.py already neutralises. Benign URLs were harvested
    at page level and so nearly always carry a path, while phishing feeds list
    bare domains:

        share of rows that are a bare domain (no path)
            benign      0.1%
            defacement  0.0%
            malware     3.0%
            phishing   23.1%

        of ALL bare-domain rows in the dataset, 98.8% are malicious

    A model trained on this learns "no path -> malicious", which is ~99% correct
    on the dataset and absurd in the real world: it labelled github.com,
    google.com, amazon.com and wikipedia.org as Malicious with 100% confidence,
    while the same domains WITH a path came back Benign.

    THE FIX
    -------
    For a fraction of rows, add a host-only duplicate carrying the SAME label.
    If mp3raid.com/music/x.html is benign then the host mp3raid.com is benign
    too, so the label transfers soundly. This puts bare domains in both classes,
    so "has no path" stops being predictive and the model is pushed onto the
    hostname's actual lexical structure.
    """
    stripped = frame["url"].str.replace(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", regex=True)
    hosts = stripped.str.split("/", n=1).str[0].str.split("?", n=1).str[0]

    has_path = stripped.str.contains("/", regex=False)
    candidates = frame[has_path & hosts.str.contains(".", regex=False)]
    if candidates.empty:
        return frame

    extra = candidates.sample(
        n=int(len(candidates) * fraction), random_state=RANDOM_STATE
    ).copy()
    extra["url"] = hosts.loc[extra.index]
    extra = extra[extra["url"].str.len() > 3].drop_duplicates(subset=["url", "label"])

    out = pd.concat([frame, extra], ignore_index=True)
    print(
        f"Added {len(extra):,} bare-domain variants "
        f"(benign {int((extra['label'] == 0).sum()):,} / malicious {int((extra['label'] == 1).sum()):,}) "
        f"to break the no-path artifact."
    )
    return out.reset_index(drop=True)


def take_sample(frame: pd.DataFrame) -> pd.DataFrame:
    """Stratified random sample of SAMPLE_SIZE rows (label proportions kept)."""
    if SAMPLE_SIZE is None or SAMPLE_SIZE >= len(frame):
        return frame.reset_index(drop=True)

    sampled, _ = train_test_split(
        frame,
        train_size=SAMPLE_SIZE,
        stratify=frame["label"],
        random_state=RANDOM_STATE,
    )
    return sampled.reset_index(drop=True)


def train_and_cache() -> dict:
    """Train the model end to end, save the bundle, and return it."""
    print(f"Loading dataset from {DATA_PATH} ...")
    frame = load_dataset()
    print(f"Loaded {len(frame):,} rows.")

    frame = take_sample(frame)
    sample_size = int(len(frame))
    print(f"Using a stratified sample of {sample_size:,} rows.")

    frame = add_bare_domain_variants(frame)

    print(f"Extracting {len(FEATURE_NAMES)} features per URL ...")
    X = featurize(frame["url"].tolist())
    y = frame["label"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    print(f"Train rows: {len(X_train):,}   Test rows: {len(X_test):,}")

    print(f"Training RandomForestClassifier(n_estimators={N_ESTIMATORS}) ...")
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=None,
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train, y_train)

    print("Evaluating on the held-out test set ...")
    y_pred = model.predict(X_test)

    importances = np.asarray(model.feature_importances_, dtype=float)
    order = np.argsort(importances)[::-1][:TOP_FEATURE_COUNT]
    top_features = [[FEATURE_NAMES[i], float(importances[i])] for i in order]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": [[int(v) for v in row] for row in confusion_matrix(y_test, y_pred)],
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "sample_size": sample_size,
        "top_features": top_features,
    }

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "metrics": metrics,
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    # compress=3 takes the bundle from ~571 MB to ~113 MB for a few seconds of
    # CPU, which makes the trained model small enough to ship or copy around.
    joblib.dump(bundle, MODEL_PATH, compress=3)
    print(f"Saved model bundle to {MODEL_PATH}")

    return bundle


def print_metrics(metrics: dict) -> None:
    """Print a readable summary of the measured metrics."""
    cm = metrics["confusion_matrix"]
    tn, fp = cm[0][0], cm[0][1]
    fn, tp = cm[1][0], cm[1][1]

    print()
    print("=" * 52)
    print("Malicious URL Detection - training results")
    print("=" * 52)
    print(f"Sample size      : {metrics['sample_size']:,}")
    print(f"Train / test rows: {metrics['n_train']:,} / {metrics['n_test']:,}")
    print()
    print(f"Accuracy         : {metrics['accuracy']:.4f}")
    print(f"Precision        : {metrics['precision']:.4f}")
    print(f"Recall           : {metrics['recall']:.4f}")
    print(f"F1 score         : {metrics['f1']:.4f}")
    print()
    print("Confusion matrix (rows = actual, cols = predicted)")
    print("                  pred benign   pred malicious")
    print(f"  actual benign   {tn:>11,}   {fp:>14,}")
    print(f"  actual malicious{fn:>11,}   {tp:>14,}")
    print()
    print(f"Top {len(metrics['top_features'])} feature importances")
    for rank, (name, importance) in enumerate(metrics["top_features"], start=1):
        print(f"  {rank:>2}. {name:<28} {importance:.5f}")
    print("=" * 52)


if __name__ == "__main__":
    saved_bundle = train_and_cache()
    print_metrics(saved_bundle["metrics"])

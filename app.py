"""Flask web application for real-time malicious URL and phishing detection.

Serves a small dashboard plus a JSON API backed by the cached scikit-learn model
produced by train.py. The model bundle is loaded once at import time; if the
cache is missing the model is trained first.

Important: this application NEVER fetches or opens the submitted URL over the
network. It classifies the URL string only - visiting a possibly malicious URL
would be unsafe and is out of scope for this project.

Endpoints:
    GET  /                  dashboard rendered from templates/index.html
    POST /api/predict       {"url": "..."} -> single prediction
    POST /api/predict_batch {"urls": [...]} -> up to 200 predictions
"""

import os
from pathlib import Path

import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request

import train
from features import FEATURE_NAMES, extract_features, featurize

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model_cache" / "model.joblib"

# Maximum number of URLs accepted by a single /api/predict_batch call.
MAX_BATCH = 200
# Number of feature names reported back with each prediction.
TOP_FEATURE_COUNT = 5


def load_bundle():
    """Return the cached model bundle, training and caching it if needed."""
    if not MODEL_PATH.exists():
        return train.train_and_cache()
    return joblib.load(MODEL_PATH)


BUNDLE = load_bundle()
MODEL = BUNDLE["model"]
BUNDLE_FEATURE_NAMES = BUNDLE.get("feature_names", FEATURE_NAMES)
METRICS = BUNDLE.get("metrics", {})


def _rank_features():
    """Return feature names ordered from most to least important for the model.

    Falls back to the declared feature order when the estimator exposes neither
    feature_importances_ nor coef_.
    """
    scores = None
    if hasattr(MODEL, "feature_importances_"):
        scores = np.asarray(MODEL.feature_importances_, dtype=float)
    elif hasattr(MODEL, "coef_"):
        scores = np.abs(np.asarray(MODEL.coef_, dtype=float)).ravel()

    if scores is None or scores.shape[0] != len(BUNDLE_FEATURE_NAMES):
        return list(BUNDLE_FEATURE_NAMES)

    order = np.argsort(scores)[::-1]
    return [BUNDLE_FEATURE_NAMES[i] for i in order]


RANKED_FEATURES = _rank_features()
TOP_FEATURES = RANKED_FEATURES[:TOP_FEATURE_COUNT]

app = Flask(__name__)


def _label(value):
    """Map a 0/1 class value to the contract's prediction string."""
    return "Malicious" if int(value) == 1 else "Benign"


def _confidence(model, row_proba, predicted_class):
    """Probability the model assigned to the class it actually predicted."""
    classes = list(model.classes_)
    try:
        index = classes.index(predicted_class)
    except ValueError:
        return float(np.max(row_proba))
    return float(row_proba[index])


def _top_features_for(url):
    """Feature name/value pairs for this URL, most important features first."""
    values = extract_features(url)
    return [
        {"name": name, "value": float(values.get(name, 0.0))}
        for name in TOP_FEATURES
    ]


def _predict_many(urls):
    """Classify a list of URL strings and return result dicts in input order."""
    matrix = featurize(urls)
    predictions = MODEL.predict(matrix)
    probabilities = MODEL.predict_proba(matrix)

    results = []
    for url, predicted, row_proba in zip(urls, predictions, probabilities):
        results.append(
            {
                "url": url,
                "prediction": _label(predicted),
                "confidence": round(_confidence(MODEL, row_proba, predicted), 4),
                "top_features": _top_features_for(url),
            }
        )
    return results


@app.route("/")
def index():
    return render_template("index.html", metrics=METRICS)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Field 'url' is required and must be a non-empty string."}), 400

    return jsonify(_predict_many([url.strip()])[0])


@app.route("/api/predict_batch", methods=["POST"])
def api_predict_batch():
    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls")

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Field 'urls' is required and must be a non-empty list."}), 400

    cleaned = [u.strip() for u in urls if isinstance(u, str) and u.strip()]
    if not cleaned:
        return jsonify({"error": "Field 'urls' contained no non-empty strings."}), 400

    if len(cleaned) > MAX_BATCH:
        return (
            jsonify({"error": "At most %d urls are allowed per request." % MAX_BATCH}),
            400,
        )

    return jsonify({"results": _predict_many(cleaned)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=port, debug=debug)

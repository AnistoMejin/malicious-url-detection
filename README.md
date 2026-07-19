# Machine Learning Based Approach for Real-Time Malicious URL and Phishing Detection

A college mini-project that classifies a URL **string** as `Malicious` or `Benign` using a
machine learning model trained on lexical and host-based features.

The system consists of:

- a feature extractor that turns a raw URL into a fixed, ordered numeric feature vector,
- a scikit-learn classifier trained on a public Kaggle dataset of ~651k labelled URLs,
- a small Flask web app with an HTML page and a JSON API for single and batch prediction.

Important: the project **never fetches or opens any URL over the network**. Only the URL text
itself is analysed. Visiting a suspected malicious URL to inspect it would be unsafe and is out
of scope for this project.

---

## Dataset

- **Name:** Malicious URLs dataset
- **Source:** https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
- **File:** `data/malicious_phish.csv`

The 44 MB CSV is not committed to git. Fetch it before the first run:

```bash
curl -sL -o data/kaggle.zip https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset
unzip -o data/kaggle.zip -d data && rm data/kaggle.zip
```

The trained model (`model_cache/`, ~571 MB) is not committed either - run
`python train.py` to regenerate it.
- **Rows:** 651,191
- **Columns:** `url,type`

Class distribution of the `type` column:

| type       | rows    |
|------------|---------|
| benign     | 428,103 |
| defacement | 96,457  |
| phishing   | 94,111  |
| malware    | 32,520  |

The project treats this as a **binary** problem. The `type` column is mapped to a label as:

| type       | label |
|------------|-------|
| benign     | 0     |
| defacement | 1     |
| phishing   | 1     |
| malware    | 1     |

So label `0` = Benign and label `1` = Malicious (any of defacement, phishing, malware).

---

## Project structure

```
malicious-url-detection/
  data/
    malicious_phish.csv      dataset (651,191 rows) - not modified by the code
  model_cache/
    model.joblib             trained model bundle, created by train.py
  templates/
    index.html               web page served at GET /
  features.py                feature extraction (FEATURE_NAMES, extract_features, featurize)
  train.py                   trains the model and writes model_cache/model.joblib
  app.py                     Flask app: web page + JSON API
  test_app.py                tests
  requirements.txt           pinned dependencies
  README.md                  this file
```

All paths inside the code are resolved relative to the source file using `pathlib`, so the
project can be moved or cloned to any directory.

---

## Install and run

Requires **Python 3**. Only pandas, numpy, scikit-learn, joblib and flask are used.

From the project root (`C:\User\Anisto\Project\malicious-url-detection`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the web app:

```powershell
python app.py
```

Then open http://127.0.0.1:5000 in a browser.

The app loads `model_cache/model.joblib` at import time. If that file does not exist, the app
trains the model first, which takes a few minutes the first time. To avoid the wait on first
request, run the training step yourself (below) before starting the server.

The port is read from the `PORT` environment variable and defaults to `5000`:

```powershell
$env:PORT = "8000"
python app.py
```

---

## Training

```powershell
python train.py
```

This reads `data/malicious_phish.csv`, maps the labels to the binary target, extracts features,
fits the classifier, evaluates it on a held-out test split, prints the metrics, and saves the
bundle to `model_cache/model.joblib`.

The saved bundle is a dict:

```python
{
  "model": <fitted sklearn estimator>,
  "feature_names": FEATURE_NAMES,
  "metrics": {
    "accuracy": ..., "precision": ..., "recall": ..., "f1": ...,
    "confusion_matrix": [[tn, fp], [fn, tp]],
    "n_train": ..., "n_test": ..., "sample_size": ...
  }
}
```

`train.py` can also be imported and called programmatically:

```python
from train import train_and_cache
bundle = train_and_cache()
print(bundle["metrics"])
```

## Measured results

Real numbers from `python train.py` on a 200,000-row stratified sample
(160,000 train / 40,000 held-out test):

| Metric | Value |
|---|---|
| Accuracy | **92.57%** |
| Precision | 90.94% |
| Recall | 86.98% |
| F1 score | **88.91%** |

Confusion matrix (rows = actual, cols = predicted):

|  | pred benign | pred malicious |
|---|---|---|
| **actual benign** | 25,109 | 1,188 |
| **actual malicious** | 1,784 | 11,919 |

Top features: `path_length`, `count_dot`, `hostname_entropy`, `tld_length`,
`count_slash`, `num_subdomains`, `url_entropy`, `hostname_length`.

### Important: a dataset artifact was removed before these numbers were produced

An earlier build scored **95.80% accuracy / 93.82% F1** - and classified
`https://www.google.com`, `https://github.com` and `https://en.wikipedia.org`
as **Malicious** with 87-98% confidence.

The cause was leakage in `malicious_phish.csv`. The `http(s)://` scheme is a
collection artifact, not a security signal:

| class | share carrying a scheme |
|---|---|
| benign | 8.3% |
| phishing | 26.4% |
| malware | 96.3% |
| defacement | 100.0% |

The model had simply learned "starts with `http://` -> malicious". Since real
URLs a user types almost always carry a scheme, the detector was useless in
practice despite the higher score.

Fix: `features.py` now strips the scheme during normalisation and the
`uses_https` feature was deleted (30 features remain, down from 31). Accuracy
fell from 95.80% to 92.57% - the lower figure is the honest one, and the model
now classifies well-known benign sites correctly.

**Takeaway for the report/viva:** the drop from 95.80% to 92.57% is a result,
not a regression.

To retrain from scratch, delete `model_cache/model.joblib` and run `python train.py` again.

---

## API

### `GET /`

Renders `templates/index.html` with the metrics from the cached model bundle. This is the
human-facing page with a box to paste a URL into.

### `POST /api/predict`

Classify a single URL.

Request body:

```json
{"url": "http://paypal-secure-login.verify-account.example.com/login.php?id=7741"}
```

Example request:

```bash
curl -X POST http://127.0.0.1:5000/api/predict \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"http://paypal-secure-login.verify-account.example.com/login.php?id=7741\"}"
```

Example response:

```json
{
  "url": "http://paypal-secure-login.verify-account.example.com/login.php?id=7741",
  "prediction": "Malicious",
  "confidence": 0.94,
  "top_features": [
    {"name": "url_length", "value": 72.0},
    {"name": "num_dots", "value": 4.0},
    {"name": "has_https", "value": 0.0}
  ]
}
```

`prediction` is always the literal string `"Malicious"` or `"Benign"`. `confidence` is a float
between 0 and 1. `top_features` lists the features that contributed most to the decision for
this URL.

### `POST /api/predict_batch`

Classify several URLs in one call.

Request body:

```json
{"urls": ["https://www.wikipedia.org/", "http://192.168.4.11/admin/cmd.exe"]}
```

Example request:

```bash
curl -X POST http://127.0.0.1:5000/api/predict_batch \
  -H "Content-Type: application/json" \
  -d "{\"urls\": [\"https://www.wikipedia.org/\", \"http://192.168.4.11/admin/cmd.exe\"]}"
```

Example response:

```json
{
  "results": [
    {
      "url": "https://www.wikipedia.org/",
      "prediction": "Benign",
      "confidence": 0.97,
      "top_features": [
        {"name": "has_https", "value": 1.0},
        {"name": "url_length", "value": 26.0}
      ]
    },
    {
      "url": "http://192.168.4.11/admin/cmd.exe",
      "prediction": "Malicious",
      "confidence": 0.89,
      "top_features": [
        {"name": "has_ip_host", "value": 1.0},
        {"name": "has_exe_extension", "value": 1.0}
      ]
    }
  ]
}
```

The `results` array preserves the order of the submitted `urls`.

Note: the confidence values, feature names and feature values shown above are illustrative
response shapes, not measurements. Real values come from your own trained model.

---

## Tests

```powershell
python -m pytest test_app.py -v
```

or, if pytest is not installed:

```powershell
python -m unittest test_app.py -v
```

The tests cover feature extraction (stable `FEATURE_NAMES` order, `featurize` shape and row
order) and the API endpoints (response keys, prediction values, batch ordering).

---

## Limitations

- **Only lexical and host-based features are used.** Every feature is derived from the URL
  string itself - length, character counts, token patterns, host shape, TLD, presence of an IP
  address literal, and similar. The project **never fetches page content**, so the "content
  features" mentioned in the project deck are **not implemented**. This is a deliberate safety
  decision: downloading a suspected malicious page is unsafe and out of scope.
- **Training uses a 200,000 row stratified sample by default**, not the full 651,191 rows, to
  keep training time and memory usage reasonable on a normal laptop. Metrics are therefore
  measured on that sample, and results may shift if the full dataset is used.
- **A malicious page served from a benign-looking URL cannot be detected.** If an attacker
  compromises a legitimate, ordinary-looking domain, or uses a well-formed short URL, the URL
  string carries no signal and the model will call it benign.
- The dataset is a static public snapshot. Attacker URL patterns drift over time, so accuracy on
  live traffic today will be lower than the offline test figures.
- The binary mapping collapses defacement, phishing and malware into a single "malicious" class,
  so the system does not tell you *which* kind of threat a URL is.
- This is a college mini-project and a learning exercise. It is not a hardened security control
  and should not be used as the only defence in a real environment.

"""End-to-end tests for the malicious URL detection mini-project.

These tests exercise the real code - the real feature extractor and the real
trained model. Nothing is mocked. No URL is ever fetched over the network;
every URL below is treated purely as a string.

Run with:  pytest tests/test_project.py
"""

import sys
from pathlib import Path

import numpy as np
import pytest

# Make the project root importable no matter where pytest is invoked from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import features  # noqa: E402
from features import FEATURE_NAMES, extract_features, featurize  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

HOSTILE_URLS = [
    "",
    "   ",
    "not a url",
    "http://",
    "///",
    "a" * 5000,
    "http://xn--80ak6aa92e.com/你好/éèê",
    "http://[::1]/",
    "br-icloud.com.br",
]

SAMPLE_URLS = [
    "http://www.google.com/",
    "http://192.168.0.1/login",
    "br-icloud.com.br",
]


def _find_feature(*substrings):
    """Return the first FEATURE_NAMES entry whose name contains all substrings.

    The exact feature naming is up to features.py, so the tests resolve the
    name instead of hardcoding one spelling.
    """
    for name in FEATURE_NAMES:
        low = name.lower()
        if all(s in low for s in substrings):
            return name
    return None


@pytest.fixture(scope="session")
def client():
    """Flask test client backed by the real model bundle.

    Importing app trains the model if the cache is missing, so this can be
    slow the very first time it runs.
    """
    import app as app_module

    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


# --------------------------------------------------------------------------
# features.py
# --------------------------------------------------------------------------

def test_feature_names_is_a_nonempty_ordered_list_of_unique_strings():
    assert isinstance(FEATURE_NAMES, list)
    assert len(FEATURE_NAMES) > 0
    assert all(isinstance(n, str) and n for n in FEATURE_NAMES)
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES), "feature names must be unique"


def test_extract_features_returns_exactly_the_feature_names_keys():
    feats = extract_features("http://www.example.com/path?q=1")
    assert isinstance(feats, dict)
    assert set(feats.keys()) == set(FEATURE_NAMES)
    assert len(feats) == len(FEATURE_NAMES)


def test_extract_features_values_are_finite_numbers():
    feats = extract_features("http://www.example.com/path?q=1")
    for name, value in feats.items():
        assert isinstance(value, (int, float)) and not isinstance(value, bool), (
            "feature %r should be numeric, got %r" % (name, type(value))
        )
        assert np.isfinite(float(value)), "feature %r is not finite" % name


@pytest.mark.parametrize("url", HOSTILE_URLS, ids=lambda u: repr(u[:20]))
def test_extract_features_never_raises_on_hostile_input(url):
    feats = extract_features(url)
    assert set(feats.keys()) == set(FEATURE_NAMES)
    for name, value in feats.items():
        assert np.isfinite(float(value)), "feature %r is not finite for %r" % (name, url[:40])


def test_featurize_shape():
    matrix = featurize(SAMPLE_URLS)
    assert matrix.shape == (len(SAMPLE_URLS), len(FEATURE_NAMES))


def test_featurize_handles_hostile_input():
    matrix = featurize(HOSTILE_URLS)
    assert matrix.shape == (len(HOSTILE_URLS), len(FEATURE_NAMES))
    assert np.isfinite(np.asarray(matrix, dtype=float)).all()


def test_featurize_preserves_row_order():
    matrix = featurize(SAMPLE_URLS)
    for i, url in enumerate(SAMPLE_URLS):
        expected = [float(extract_features(url)[name]) for name in FEATURE_NAMES]
        assert list(np.asarray(matrix[i], dtype=float)) == expected, (
            "row %d does not match extract_features for %r" % (i, url)
        )


def test_featurize_row_order_is_not_sorted_or_deduplicated():
    urls = ["zzz.com", "aaa.com", "zzz.com"]
    matrix = featurize(urls)
    assert matrix.shape[0] == 3
    # first and third are the same URL, so their rows must be identical
    assert list(np.asarray(matrix[0], dtype=float)) == list(np.asarray(matrix[2], dtype=float))
    # first row must correspond to "zzz.com", not to the sorted-first "aaa.com"
    expected_zzz = [float(extract_features("zzz.com")[n]) for n in FEATURE_NAMES]
    assert list(np.asarray(matrix[0], dtype=float)) == expected_zzz


def test_featurize_accepts_an_empty_sequence():
    matrix = featurize([])
    assert matrix.shape[0] == 0


def test_ip_host_sets_the_is_ip_feature():
    ip_feature = _find_feature("ip")
    assert ip_feature is not None, "expected an IP-address feature in FEATURE_NAMES"

    assert extract_features("http://192.168.0.1/login")[ip_feature] == 1
    assert extract_features("http://www.google.com/")[ip_feature] == 0


def test_known_shortener_sets_the_shortener_feature():
    short_feature = _find_feature("short")
    assert short_feature is not None, "expected a URL-shortener feature in FEATURE_NAMES"

    assert extract_features("http://bit.ly/abc")[short_feature] == 1
    assert extract_features("http://www.google.com/")[short_feature] == 0


def test_extract_features_is_deterministic():
    url = "http://paypal.com.secure-login.example.ru/verify?id=99"
    assert extract_features(url) == extract_features(url)


# --------------------------------------------------------------------------
# app.py
# --------------------------------------------------------------------------

def test_index_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200


def test_predict_returns_a_valid_prediction(client):
    response = client.post("/api/predict", json={"url": "http://www.google.com/"})
    assert response.status_code == 200

    body = response.get_json()
    assert body["url"] == "http://www.google.com/"
    assert body["prediction"] in ("Malicious", "Benign")
    assert isinstance(body["confidence"], float)
    assert 0.0 <= body["confidence"] <= 1.0
    assert "top_features" in body


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"url": ""},
        {"url": "   "},
        {"url": None},
        {"url": 12345},
        {"url": ["http://www.google.com/"]},
    ],
    ids=["missing", "empty", "whitespace", "none", "int", "list"],
)
def test_predict_rejects_bad_url(client, payload):
    response = client.post("/api/predict", json=payload)
    assert response.status_code == 400


def test_predict_handles_a_hostile_url_without_crashing(client):
    response = client.post("/api/predict", json={"url": "a" * 5000})
    assert response.status_code in (200, 400)
    if response.status_code == 200:
        assert response.get_json()["prediction"] in ("Malicious", "Benign")


def test_predict_batch_returns_results_in_input_order(client):
    urls = [
        "http://www.google.com/",
        "http://192.168.0.1/login",
        "br-icloud.com.br",
    ]
    response = client.post("/api/predict_batch", json={"urls": urls})
    assert response.status_code == 200

    results = response.get_json()["results"]
    assert len(results) == 3
    assert [r["url"] for r in results] == urls

    for result in results:
        assert result["prediction"] in ("Malicious", "Benign")
        assert 0.0 <= result["confidence"] <= 1.0


def test_predict_batch_agrees_with_single_predict(client):
    url = "http://192.168.0.1/login"

    single = client.post("/api/predict", json={"url": url}).get_json()
    batch = client.post("/api/predict_batch", json={"urls": [url]}).get_json()["results"][0]

    assert single["prediction"] == batch["prediction"]
    assert single["confidence"] == pytest.approx(batch["confidence"])


@pytest.mark.parametrize(
    "payload",
    [{"urls": []}, {}, {"urls": None}, {"urls": "http://www.google.com/"}],
    ids=["empty", "missing", "none", "string"],
)
def test_predict_batch_rejects_bad_payload(client, payload):
    response = client.post("/api/predict_batch", json=payload)
    assert response.status_code == 400


# --------------------------------------------------------------------------
# model bundle
# --------------------------------------------------------------------------

def test_cached_bundle_has_the_contract_keys():
    import joblib

    import app as app_module  # ensures the cache exists

    cache_path = PROJECT_ROOT / "model_cache" / "model.joblib"
    assert cache_path.exists(), "expected the model cache at %s" % cache_path

    bundle = joblib.load(cache_path)
    assert set(bundle.keys()) >= {"model", "feature_names", "metrics"}
    assert bundle["feature_names"] == features.FEATURE_NAMES

    metrics = bundle["metrics"]
    expected = {
        "accuracy",
        "precision",
        "recall",
        "f1",
        "confusion_matrix",
        "n_train",
        "n_test",
        "sample_size",
    }
    assert set(metrics.keys()) >= expected

    # No specific accuracy is asserted - it is data dependent. Only sanity bounds.
    for key in ("accuracy", "precision", "recall", "f1"):
        assert 0.0 <= float(metrics[key]) <= 1.0
    assert int(metrics["n_train"]) > 0
    assert int(metrics["n_test"]) > 0

    assert app_module.app is not None

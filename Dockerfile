# Malicious URL Detection - self-contained image.
#
# The 44 MB dataset and the trained model are gitignored, so a clone alone
# cannot run. This image fetches the dataset and trains the model during the
# build, so the container starts serving immediately.
#
#   docker build -t malicious-url-detection .
#   docker run --rm -p 5000:5000 malicious-url-detection
#   -> http://localhost:5000
#
# The build takes roughly 5-8 minutes, most of it training. Run it once; after
# that "docker run" is instant.

FROM python:3.12-slim

WORKDIR /app

# curl and unzip are needed only to fetch the dataset during the build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip \
 && rm -rf /var/lib/apt/lists/*

# Install dependencies first so this layer caches across code edits.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fetch the dataset (public, no Kaggle account required) -> data/malicious_phish.csv
RUN mkdir -p data \
 && curl -sSL -o /tmp/kaggle.zip \
      "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset" \
 && unzip -o /tmp/kaggle.zip -d data \
 && rm /tmp/kaggle.zip \
 && test -s data/malicious_phish.csv

# Train during the build so the image ships with model_cache/model.joblib.
# Without this every "docker run" on a fresh container would retrain.
RUN python train.py

EXPOSE 5000
ENV PORT=5000 \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

CMD ["python", "app.py"]

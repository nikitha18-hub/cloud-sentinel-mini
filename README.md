# CloudSentinel Mini

CloudSentinel Mini is an educational cloud security configuration scanner. It evaluates five boolean settings against simulated data only; it does not connect to AWS or inspect real infrastructure.

## Run locally

1. Install Python 3.9 or newer.
2. Install dependencies with `pip install -r requirements.txt`.
3. Start the app with `python app.py`.
4. Open `http://127.0.0.1:5000` in your browser.

## API

- `GET /api/sample` returns the simulated example configuration.
- `POST /api/scan` accepts a JSON object containing all five boolean settings and returns the score, counts, and five check results.
- `POST /api/report` accepts `{"results": [...]}`, saves a CSV under `reports/`, and downloads it.

The required configuration keys are `public_storage_access`, `encryption_enabled`, `logging_enabled`, `unrestricted_ssh`, and `excessive_iam_admin`.

## Run tests

Run `python -m unittest discover -s tests`.

The scanner is a learning demo, not a substitute for reviewing or securing actual cloud infrastructure.

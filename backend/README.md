# Risk scoring backend

Anomaly detection + trend/acceleration + coordinated escalation forecast.

## Run

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

API: http://localhost:8000

- **POST /predict** — body `{ "events": [ ... ] }` (same event shape as frontend). Returns `{ anomalyScore, message, coordinatedEscalation, trendSummary }`.
- **POST /add-data** — body `{ "events": [ ... ] }`. Appends events and retrains the model.
- **GET /health** — `{ "status": "ok" }`.

## Logic

- 15-min windows, features per (window, source IP): counts (auth fail/success, DNS, firewall allow/block, malware, high/critical severity).
- TensorFlow autoencoder (9→6→3→6→9) for anomaly score (0–1, higher = more unusual; reconstruction MSE normalized by max training MSE).
- Trend = slope of last 5 windows’ scores per IP; acceleration = change in slope.
- Coordinated escalation = 2+ IPs with rising trend and positive acceleration → message: "High likelihood of coordinated escalation in the next 15 minutes."

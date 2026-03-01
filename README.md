# UAInnovateCyberSecurity

## Risk forecast (ML backend)

The dashboard can show a **risk forecast** (anomaly score + coordinated escalation message) when the Python backend is running.

1. Start the backend: `cd backend && pip install -r requirements.txt && uvicorn app:app --reload --port 8000`
2. Open the frontend (e.g. `frontend/index.html` or a static server). Load CSV data.
3. The **Risk forecast** box (two lines) appears above the threat cards: anomaly score + trend summary, then the message (Normal / Elevated / "High likelihood of coordinated escalation in the next 15 minutes").
4. On CSV load, events are sent to `POST /add-data` so the model can retrain. Predictions are throttled to every 2s during replay.
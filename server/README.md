# Alert server (SMS + Email)

When the dashboard detects a **high-risk incident** (severity ≥ 70), it can send an **email** (via Resend) and/or an **SMS** (via Twilio). This server receives alert requests from the dashboard.

**Email (Resend)** works on free tiers and is a good option if Twilio SMS is blocked (e.g. US 10DLC on trial). **SMS (Twilio)** may require A2P 10DLC registration in the US for delivery.

## 1. Install dependencies

From this folder (`server/`):

```bash
npm install
```

## 2. Get Twilio credentials

1. Sign up at **https://www.twilio.com/try-twilio** (free trial gives you credit).
2. In the Twilio Console (**https://console.twilio.com**), note:
   - **Account SID** (starts with `AC...`) — on the dashboard home.
   - **Auth Token** — click “Show” to reveal it.
3. Get a **phone number** for sending SMS:
   - Go to **Phone Numbers → Manage → Buy a number** (trial accounts get one free).
   - Pick a number with SMS capability. That number will be the “from” for alerts.

## 3. Configure environment

**From the `server` folder** (the same folder that has `package.json` and `index.js`):

1. Copy the example file to create your real `.env` file:
   ```bash
   cp .env.example .env
   ```
   (That’s two separate commands if you’re elsewhere: first `cd server`, then `cp .env.example .env`.)

2. Open `.env` in any text editor (Cursor, Notepad, TextEdit, etc.). You’ll see something like:
   ```
   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TWILIO_AUTH_TOKEN=your_auth_token_here
   TWILIO_PHONE_NUMBER=+1234567890
   ```

3. Replace those placeholder values. **No spaces around the `=`**.
   - **For email (recommended, works on free tier):** Sign up at **https://resend.com**, create an API key, and set:
     - `RESEND_API_KEY=` your Resend API key (starts with `re_`).
     - Optionally `FROM_EMAIL=alerts@yourdomain.com` (default is `onboarding@resend.dev` for testing; Resend may restrict who you can send to until you add a domain).
   - **For SMS (Twilio):** `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_PHONE_NUMBER` as above. US delivery may require 10DLC registration.

Save the file. **Do not commit `.env`** — it’s in `.gitignore`.

## 4. Run the server

```bash
npm start
```

You should see: `Alert server running at http://localhost:3001`.  
If Twilio isn’t configured, you’ll see a warning but the server still runs (the dashboard will get a “not configured” error when you try to send).

## 5. Run the dashboard and test

1. Start the **dashboard** (from `dashboard/`): `npm run dev`.
2. In the sidebar under **Alerts for suspicious activity**, enter your **email** (and optionally phone). Click **Save**.
3. Load data that produces a high-risk incident. An alert is sent automatically: email if configured and you have `RESEND_API_KEY` set; SMS if configured and Twilio is set up.
4. Check your email (and phone if SMS was sent). The toast will say e.g. "Email sent to you@example.com".

## API

- **POST /api/alert** — body: `{ "to": "+15551234567", "message": "..." }`. Sends SMS via Twilio.
- **POST /api/alert-email** — body: `{ "to": "you@example.com", "message": "..." }`. Sends email via Resend.
- **GET /api/health** — returns `{ "ok": true, "smsConfigured": true|false, "emailConfigured": true|false }`.

## Troubleshooting

- **“Email not configured”** — Add `RESEND_API_KEY` to `.env` (get one at https://resend.com).
- **Resend: can only send to own email** — Free tier may restrict recipients; use your Resend account email to test.
- **“SMS not configured”** — `.env` is missing or Twilio vars are empty. Check the server console on startup.
- **Twilio error 21211** — “To” number is invalid. Use E.164 (e.g. `+15551234567`).
- **Twilio 30034 (10DLC)** — US SMS from an unregistered number; register for A2P 10DLC or use email instead.
- **Trial: can only send to verified numbers** — In Twilio Console, verify the destination number under Verified Caller IDs.

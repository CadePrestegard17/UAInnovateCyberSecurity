require('dotenv').config();
const express = require('express');
const cors = require('cors');
const twilio = require('twilio');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const fromNumber = process.env.TWILIO_PHONE_NUMBER;
const resendApiKey = (process.env.RESEND_API_KEY || '').trim();
const fromEmail = (process.env.FROM_EMAIL || 'onboarding@resend.dev').trim();
const resend = resendApiKey ? new Resend(resendApiKey) : null;

function getTwilioClient() {
  if (!accountSid || !authToken) return null;
  return twilio(accountSid, authToken);
}

app.post('/api/alert', async (req, res) => {
  const { to, message } = req.body;
  if (!to || !message) {
    return res.status(400).json({ error: 'Missing "to" or "message" in body' });
  }

  const client = getTwilioClient();
  if (!client) {
    return res.status(503).json({
      error: 'SMS not configured. Add TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_PHONE_NUMBER to server/.env',
    });
  }

  if (!fromNumber) {
    return res.status(503).json({
      error: 'TWILIO_PHONE_NUMBER not set in server/.env',
    });
  }

  try {
    const result = await client.messages.create({
      body: message,
      from: fromNumber,
      to: to.trim(),
    });
    return res.json({ success: true, sid: result.sid });
  } catch (err) {
    console.error('Twilio error:', err.message);
    return res.status(500).json({
      error: err.message || 'Failed to send SMS',
    });
  }
});

app.post('/api/alert-email', async (req, res) => {
  const { to, message } = req.body;
  if (!to || !message) {
    return res.status(400).json({ error: 'Missing "to" or "message" in body' });
  }

  if (!resend) {
    return res.status(503).json({
      error: 'Email not configured. Add RESEND_API_KEY to server/.env (get one at https://resend.com)',
    });
  }

  const toEmail = to.trim();
  console.log('[alert-email] Sending to:', toEmail);

  try {
    const { data, error } = await resend.emails.send({
      from: fromEmail,
      to: toEmail,
      subject: 'SOC Alert: High-risk incident',
      text: message,
    });
    if (error) {
      const errMsg = typeof error === 'object' && error !== null && 'message' in error ? error.message : String(error);
      console.error('[alert-email] Resend error:', errMsg);
      return res.status(400).json({ error: errMsg || 'Failed to send email' });
    }
    console.log('[alert-email] Sent, id:', data?.id);
    return res.json({ success: true, id: data?.id });
  } catch (err) {
    console.error('[alert-email] Exception:', err);
    const errMsg = err && err.message ? err.message : String(err);
    return res.status(500).json({
      error: errMsg || 'Failed to send email',
    });
  }
});

app.get('/api/health', (req, res) => {
  const smsConfigured = !!(accountSid && authToken && fromNumber);
  const emailConfigured = !!resendApiKey;
  res.json({ ok: true, smsConfigured, emailConfigured });
});

app.listen(PORT, () => {
  console.log(`Alert server running at http://localhost:${PORT}`);
  console.log('Email configured:', !!resendApiKey ? 'yes' : 'NO - add RESEND_API_KEY to server/.env');
  if (!getTwilioClient() || !fromNumber) {
    console.warn('Twilio not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER in server/.env to send real SMS.');
  }
  if (!resendApiKey) {
    console.warn('Email not configured. Set RESEND_API_KEY in server/.env (get one at https://resend.com).');
  }
});

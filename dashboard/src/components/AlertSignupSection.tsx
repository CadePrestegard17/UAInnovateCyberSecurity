import { useState, useCallback, type ChangeEvent } from 'react';

type Props = {
  phone: string;
  onPhoneChange: (value: string) => void;
  email: string;
  onEmailChange: (value: string) => void;
};

export function AlertSignupSection({ phone, onPhoneChange, email, onEmailChange }: Props) {
  const [savedJustNow, setSavedJustNow] = useState(false);

  const handleSave = useCallback(() => {
    onPhoneChange(phone);
    onEmailChange(email);
    setSavedJustNow(true);
    window.setTimeout(() => setSavedJustNow(false), 2000);
  }, [phone, onPhoneChange, email, onEmailChange]);

  return (
    <section className="alert-signup" aria-labelledby="alert-signup-title">
      <h3 id="alert-signup-title" className="alert-signup__title">
        Alerts for suspicious activity
      </h3>
      <p className="alert-signup__desc">
        When we detect a high-risk incident, we can email you (and optionally send an SMS). Email works on free tiers; SMS may require Twilio 10DLC in the US.
      </p>
      <label className="alert-signup__label">
        <span className="alert-signup__label-text">Email</span>
        <input
          type="email"
          className="alert-signup__input"
          value={email}
          onChange={(e: ChangeEvent<HTMLInputElement>) => onEmailChange(e.target.value)}
          placeholder="you@example.com"
          aria-describedby="alert-signup-hint-email"
        />
      </label>
      <label className="alert-signup__label">
        <span className="alert-signup__label-text">Phone (optional, for SMS)</span>
        <input
          type="tel"
          className="alert-signup__input"
          value={phone}
          onChange={(e: ChangeEvent<HTMLInputElement>) => onPhoneChange(e.target.value)}
          placeholder="+15551234567"
          aria-describedby="alert-signup-hint-phone"
        />
      </label>
      <div className="alert-signup__row">
        <button type="button" className="alert-signup__save" onClick={handleSave}>
          Save
        </button>
        {savedJustNow && <span className="alert-signup__saved">Saved!</span>}
      </div>
      <p id="alert-signup-hint-email" className="alert-signup__hint">
        At least one required. Saved in this browser only (doesn’t expire).
      </p>
    </section>
  );
}

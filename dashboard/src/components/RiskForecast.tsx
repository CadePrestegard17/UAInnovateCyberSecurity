import type { RiskResponse } from '../lib/riskApi';
import clsx from 'clsx';

type Props = {
  risk: RiskResponse | null;
  loading: boolean;
  error: string | null;
};

export function RiskForecast({ risk, loading, error }: Props) {
  const howBlock = (
    <details className="risk-forecast__how">
      <summary className="risk-forecast__how-summary">How we calculate risk</summary>
      <ul className="risk-forecast__how-list">
        <li>Events are grouped into <strong>15-minute time windows</strong> and by <strong>source IP</strong>. For each window and IP we count activity types (e.g. auth failures, DNS, firewall blocks, malware).</li>
        <li>The <strong>anomaly score (0–100%)</strong> measures how unusual that pattern is compared to what we’ve seen. Higher = more unusual; low = looks normal.</li>
        <li>We track whether anomaly is <strong>trending up</strong> over recent windows and whether that trend is <strong>accelerating</strong> (getting worse faster).</li>
        <li><strong>Coordinated escalation</strong> is flagged when two or more IPs show rising and accelerating anomaly at the same time, which can indicate a coordinated attack.</li>
      </ul>
    </details>
  );

  if (loading) {
    return (
      <section className="risk-forecast">
        <h3 className="risk-forecast__title">Risk forecast</h3>
        <p className="risk-forecast__muted">Loading prediction…</p>
        {howBlock}
      </section>
    );
  }
  if (error) {
    return (
      <section className="risk-forecast">
        <h3 className="risk-forecast__title">Risk forecast</h3>
        <p className="risk-forecast__error">Backend unavailable: {error}. Start the API on port 8000 to see predictions.</p>
        {howBlock}
      </section>
    );
  }
  if (!risk) {
    return (
      <section className="risk-forecast">
        <h3 className="risk-forecast__title">Risk forecast</h3>
        <p className="risk-forecast__muted">Load data to see risk prediction.</p>
        {howBlock}
      </section>
    );
  }
  const scoreClass =
    risk.anomalyScore >= 0.7 ? 'risk-forecast__score--high' : risk.anomalyScore >= 0.4 ? 'risk-forecast__score--medium' : 'risk-forecast__score--low';
  return (
    <section className="risk-forecast">
      <h3 className="risk-forecast__title">Risk forecast</h3>
      <div className="risk-forecast__row">
        <span className={clsx('risk-forecast__score', scoreClass)}>
          Anomaly: {(risk.anomalyScore * 100).toFixed(0)}%
        </span>
        <span className="risk-forecast__trend">{risk.trendSummary}</span>
      </div>
      <p className="risk-forecast__message">{risk.message}</p>
      {risk.coordinatedEscalation && (
        <p className="risk-forecast__alert">⚠ High likelihood of coordinated escalation in the next 15 minutes.</p>
      )}
      {howBlock}
    </section>
  );
}

import { format, isValid } from 'date-fns';
import type { Incident } from '../lib/correlation';
import type { MalwareAlertRow } from '../lib/types';
import clsx from 'clsx';

type Props = {
  incident: Incident;
  malware: MalwareAlertRow[];
};

function severityClass(severity: number): string {
  if (severity >= 75) return 'severity-critical';
  if (severity >= 50) return 'severity-high';
  if (severity >= 25) return 'severity-medium';
  return 'severity-low';
}

export function SummaryCards({ incident, malware }: Props) {
  const malInfo = malware.length > 0
    ? malware.map((m) => `${m.hostname}: ${m.threat_name}`).join('; ')
    : null;

  return (
    <div className="summary-cards">
      <div className="summary-card">
        <span className="summary-card__label">Incident</span>
        <span className="summary-card__value">{incident.title}</span>
      </div>
      <div className="summary-card">
        <span className="summary-card__label">Severity</span>
        <span className={clsx('summary-card__value', 'summary-card__badge', severityClass(incident.severity))}>
          {incident.severity}
        </span>
      </div>
      <div className="summary-card">
        <span className="summary-card__label">Time range</span>
        <span className="summary-card__value">
          {isValid(incident.start) ? format(incident.start, 'yyyy-MM-dd HH:mm') : '—'} — {isValid(incident.end) ? format(incident.end, 'yyyy-MM-dd HH:mm') : '—'}
        </span>
      </div>
      <div className="summary-card">
        <span className="summary-card__label">Primary entity (IP)</span>
        <span className="summary-card__value summary-card__mono">{incident.primary_entity}</span>
      </div>
      {malInfo && (
        <div className="summary-card summary-card--full">
          <span className="summary-card__label">Malware</span>
          <span className="summary-card__value">{malInfo}</span>
        </div>
      )}
    </div>
  );
}

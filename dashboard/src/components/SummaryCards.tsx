import { format, isValid } from 'date-fns';
import { useRef, useState } from 'react';
import type { Incident } from '../lib/correlation';
import type { MalwareAlertRow } from '../lib/types';
import { SeverityBadge } from './SeverityBadge';

type Props = {
  incident: Incident;
  malware: MalwareAlertRow[];
};

export function SummaryCards({ incident, malware }: Props) {
  const malInfo = malware.length > 0
    ? malware.map((m) => `${m.hostname}: ${m.threat_name}`).join('; ')
    : null;
  const severityCardRef = useRef<HTMLDivElement>(null);
  const [severityHover, setSeverityHover] = useState(false);

  return (
    <div className="summary-cards">
      <div className="summary-card">
        <span className="summary-card__label">Incident</span>
        <span className="summary-card__value">{incident.title}</span>
      </div>
      <div
        ref={severityCardRef}
        className="summary-card summary-card--severity-hover"
        onMouseEnter={() => setSeverityHover(true)}
        onMouseLeave={() => setSeverityHover(false)}
      >
        <span className="summary-card__label">Severity</span>
        <SeverityBadge
          incident={incident}
          badgeClassName="summary-card__value summary-card__badge"
          hover={severityHover}
          anchorRef={severityCardRef}
        />
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
        <div className="summary-card summary-card--full summary-card--malware-alert">
          <span className="summary-card__label">⚠ Malware alert</span>
          <span className="summary-card__value summary-card__value--malware">{malInfo}</span>
          <p className="summary-card__malware-desc">
            Beacon-type malware suggests possible command-and-control (C2) communication. Isolate the affected host and investigate.
          </p>
        </div>
      )}
    </div>
  );
}

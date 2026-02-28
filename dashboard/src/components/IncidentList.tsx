import type { Incident } from '../lib/correlation';
import clsx from 'clsx';

type Props = {
  incidents: Incident[];
  selectedId: Incident['id'] | null;
  onSelect: (incident: Incident) => void;
};

function severityClass(severity: number): string {
  if (severity >= 75) return 'severity-critical';
  if (severity >= 50) return 'severity-high';
  if (severity >= 25) return 'severity-medium';
  return 'severity-low';
}

export function IncidentList({ incidents, selectedId, onSelect }: Props) {
  return (
    <div className="incident-list">
      <h2 className="incident-list__title">Incidents</h2>
      {incidents.length === 0 ? (
        <p className="incident-list__empty">No incidents detected. Load data and check correlation rules.</p>
      ) : (
        <ul className="incident-list__items">
          {incidents.map((inc) => (
            <li key={inc.id}>
              <button
                type="button"
                className={clsx('incident-list__item', selectedId === inc.id && 'incident-list__item--selected')}
                onClick={() => onSelect(inc)}
              >
                <span className="incident-list__item-label">{inc.id === 'CASE_A' ? 'Case A' : 'Case B'}</span>
                <span className="incident-list__item-title">{inc.title}</span>
                <span className={clsx('incident-list__badge', severityClass(inc.severity))}>
                  {inc.severity}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

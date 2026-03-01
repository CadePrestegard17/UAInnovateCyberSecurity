import type { Incident } from '../lib/correlation';
import clsx from 'clsx';
import { SeverityBadge } from './SeverityBadge';

type Props = {
  incidents: Incident[];
  selectedId: Incident['id'] | null;
  onSelect: (incident: Incident) => void;
};

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
                <SeverityBadge incident={inc} badgeClassName="incident-list__badge" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

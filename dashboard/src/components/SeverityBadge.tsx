import { useRef, useState } from 'react';
import type { Incident } from '../lib/correlation';
import { getSeverityTooltip } from '../lib/severityTooltip';
import clsx from 'clsx';

function severityClass(severity: number): string {
  if (severity >= 75) return 'severity-critical';
  if (severity >= 50) return 'severity-high';
  if (severity >= 25) return 'severity-medium';
  return 'severity-low';
}

type Props = {
  incident: Incident;
  badgeClassName?: string;
  /** When set, parent controls hover and tooltip is positioned from this element (e.g. whole card). */
  hover?: boolean;
  anchorRef?: React.RefObject<HTMLElement | null>;
};

export function SeverityBadge({ incident, badgeClassName, hover: controlledHover, anchorRef: _anchorRef }: Props) {
  const [internalHover, setInternalHover] = useState(false);
  const ownRef = useRef<HTMLSpanElement>(null);
  const hover = controlledHover ?? internalHover;
  const text = getSeverityTooltip(incident);
  const className = clsx(severityClass(incident.severity), badgeClassName);

  return (
    <span
      ref={ownRef}
      className="severity-badge-wrap"
      onMouseEnter={controlledHover === undefined ? () => setInternalHover(true) : undefined}
      onMouseLeave={controlledHover === undefined ? () => setInternalHover(false) : undefined}
    >
      <span className={className}>{incident.severity}</span>
      {hover && (
        <span className="severity-tooltip-bubble severity-tooltip-bubble--below" role="tooltip">
          {text}
        </span>
      )}
    </span>
  );
}

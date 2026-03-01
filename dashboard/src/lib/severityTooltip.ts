import type { Incident } from './correlation';

/** Detailed explanation of how severity was computed. */
export function getSeverityTooltip(incident: Pick<Incident, 'id'>): string {
  if (incident.id === 'CASE_A') {
    return (
      'Case A (Brute-force): Starts at 30, then adds half the total denied login count, plus up to +30 for ' +
      'how concentrated the attempts are in any 10‑minute window. If the same IP later had a successful login, ' +
      'that’s a +25 bonus (possible credential compromise). If malware was detected, the incident whose time ' +
      'range is closest to the malware gets +15. Final score is capped at 100.'
    );
  }
  return (
    'Case B (Beaconing): Starts at 25, then adds one-third of the DNS query count and up to +30 for the ' +
    'peak 10‑minute burst. If the host has many allowed outbound firewall connections (20+), that’s +20 ' +
    '(possible C2). If malware was detected, the incident closest in time to the malware gets +15. Capped at 100.'
  );
}

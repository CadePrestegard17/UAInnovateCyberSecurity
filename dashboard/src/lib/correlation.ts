import { isValid } from 'date-fns';
import type { NormalizedEvent } from './types';
import type { AuthLogRow, DnsLogRow, FirewallLogRow, MalwareAlertRow } from './types';
import { parseTimestamp } from './time';

const WINDOW_MINUTES = 10;
const BRUTE_FORCE_TOTAL_THRESHOLD = 25;
const BRUTE_FORCE_WINDOW_THRESHOLD = 15;
const BEACONING_TOTAL_THRESHOLD = 60;
const BEACONING_WINDOW_THRESHOLD = 30;

export type Incident = {
  id: 'CASE_A' | 'CASE_B';
  title: string;
  severity: number;
  start: Date;
  end: Date;
  primary_entity: string;
  highlights: string[];
  recommended_actions: string[];
  related_events: NormalizedEvent[];
};

function isDeniedAuth(action: string): boolean {
  const a = (action ?? '').toLowerCase();
  return a !== 'success' && a.length > 0;
}

/** Find the 10-minute window with maximum count of events (events must have valid time and pass predicate). */
function worstWindow<T>(
  events: T[],
  getTime: (e: T) => Date,
  predicate: (e: T) => boolean
): { count: number; windowStart: Date; windowEnd: Date } | null {
  const withTime = events
    .filter((e) => predicate(e) && isValid(getTime(e)))
    .map((e) => ({ e, t: getTime(e).getTime() }))
    .sort((a, b) => a.t - b.t);
  if (withTime.length === 0) return null;
  const windowMs = WINDOW_MINUTES * 60 * 1000;
  let maxCount = 0;
  let bestStart = 0;
  let bestEnd = 0;
  for (let i = 0; i < withTime.length; i++) {
    const start = withTime[i].t;
    const end = start + windowMs;
    const count = withTime.filter(({ t }) => t >= start && t < end).length;
    if (count > maxCount) {
      maxCount = count;
      bestStart = start;
      bestEnd = end;
    }
  }
  return {
    count: maxCount,
    windowStart: new Date(bestStart),
    windowEnd: new Date(bestEnd),
  };
}

/** Case A: Brute-force / credential attack detection */
function detectCaseA(
  auth: AuthLogRow[],
  allEvents: NormalizedEvent[]
): Incident | null {
  const deniedByIp = new Map<string, { total: number; byUser: Map<string, number>; events: NormalizedEvent[] }>();
  const authEvents = allEvents.filter((e) => e.source === 'auth');

  for (const row of auth) {
    const ip = (row.source_ip ?? '').trim();
    if (!ip) continue;
    const denied = isDeniedAuth(row.action ?? '');
    if (!denied) continue;
    let rec = deniedByIp.get(ip);
    if (!rec) {
      rec = { total: 0, byUser: new Map(), events: [] };
      deniedByIp.set(ip, rec);
    }
    rec.total += 1;
    rec.byUser.set(row.user, (rec.byUser.get(row.user) ?? 0) + 1);
  }

  // Attach related auth events for flagged IPs (denied + success)
  for (const ev of authEvents) {
    if (ev.entity_ip && deniedByIp.has(ev.entity_ip)) {
      deniedByIp.get(ev.entity_ip)!.events.push(ev);
    }
  }

  let bestIp: string | null = null;
  let bestTotal = 0;
  let bestWindowResult: { count: number; windowStart: Date; windowEnd: Date } | null = null;

  for (const [ip, rec] of deniedByIp) {
    const deniedList = auth.filter((r) => (r.source_ip ?? '').trim() === ip && isDeniedAuth(r.action ?? ''));
    const win = worstWindow(deniedList, (r) => parseTimestamp(r.timestamp), () => true);
    const overTotal = rec.total >= BRUTE_FORCE_TOTAL_THRESHOLD;
    const overWindow = win ? win.count >= BRUTE_FORCE_WINDOW_THRESHOLD : false;
    if (!overTotal && !overWindow) continue;
    if (rec.total > bestTotal) {
      bestTotal = rec.total;
      bestIp = ip;
      bestWindowResult = win;
    }
  }

  if (!bestIp) return null;

  const rec = deniedByIp.get(bestIp)!;
  const deniedList = auth.filter((r) => (r.source_ip ?? '').trim() === bestIp && isDeniedAuth(r.action ?? ''));
  const windowResult = bestWindowResult ?? worstWindow(deniedList, (r) => parseTimestamp(r.timestamp), () => true);
  const hasSuccessAfter = rec.events.some((e) => e.action && !isDeniedAuth(e.action));
  const successAfterDenied = auth.some(
    (r) => (r.source_ip ?? '').trim() === bestIp && !isDeniedAuth(r.action ?? '')
  );

  const targeted_users = Array.from(rec.byUser.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([u]) => u);

  let severity = Math.min(100, 30 + Math.floor(rec.total / 2) + (windowResult ? Math.min(30, windowResult.count) : 0));
  if (successAfterDenied || hasSuccessAfter) severity = Math.min(100, severity + 25);

  const start = windowResult?.windowStart ?? (rec.events.length ? rec.events[0].time : new Date(0));
  const end = windowResult?.windowEnd ?? (rec.events.length ? rec.events[rec.events.length - 1].time : new Date(0));

  const highlights: string[] = [
    `Attacker IP ${bestIp} had ${rec.total} denied authentication attempts.`,
    `Top targeted users: ${targeted_users.join(', ') || 'N/A'}.`,
  ];
  if (windowResult) {
    highlights.push(
      `Most intense 10-minute window: ${windowResult.count} denials between ${start.toISOString()} and ${end.toISOString()}.`
    );
  }
  if (successAfterDenied) {
    highlights.push('Same IP later had successful logins — possible credential compromise.');
  }

  const recommended_actions: string[] = [
    `Block IP ${bestIp} at firewall.`,
    ...targeted_users.map((u) => `Disable user ${u} / force password reset.`),
    `Search SIEM for lateral movement from ${bestIp}.`,
  ];

  const startMs = start.getTime();
  const endMs = end.getTime();
  const related_events = allEvents.filter((e) => {
    const t = e.time.getTime();
    return t >= startMs && t <= endMs;
  });

  return {
    id: 'CASE_A',
    title: 'Brute-force / credential attack',
    severity: Math.round(severity),
    start,
    end,
    primary_entity: bestIp,
    highlights,
    recommended_actions,
    related_events,
  };
}

/** Case B: Beaconing / suspicious DNS repetition */
function detectCaseB(
  dns: DnsLogRow[],
  firewall: FirewallLogRow[],
  allEvents: NormalizedEvent[]
): Incident | null {
  const key = (ip: string, domain: string) => `${ip}\t${domain}`;
  const countByKey = new Map<string, { ip: string; domain: string; events: number; times: number[] }>();

  for (const row of dns) {
    const ip = (row.client_ip ?? '').trim();
    const domain = (row.domain_queried ?? '').trim();
    if (!ip || !domain) continue;
    const k = key(ip, domain);
    let rec = countByKey.get(k);
    if (!rec) {
      rec = { ip, domain, events: 0, times: [] };
      countByKey.set(k, rec);
    }
    rec.events += 1;
    const t = parseTimestamp(row.timestamp);
    if (isValid(t)) rec.times.push(t.getTime());
  }

  let bestKey: string | null = null;
  let bestTotal = 0;
  let bestWindowCount = 0;
  let bestWindowStart = 0;
  let bestWindowEnd = 0;

  for (const [k, rec] of countByKey) {
    rec.times.sort((a, b) => a - b);
    const windowMs = WINDOW_MINUTES * 60 * 1000;
    let maxInWindow = 0;
    let winStart = 0;
    let winEnd = 0;
    for (let i = 0; i < rec.times.length; i++) {
      const start = rec.times[i];
      const end = start + windowMs;
      const inWindow = rec.times.filter((t) => t >= start && t < end).length;
      if (inWindow > maxInWindow) {
        maxInWindow = inWindow;
        winStart = start;
        winEnd = end;
      }
    }
    const overTotal = rec.events >= BEACONING_TOTAL_THRESHOLD;
    const overWindow = maxInWindow >= BEACONING_WINDOW_THRESHOLD;
    if (!overTotal && !overWindow) continue;
    if (rec.events > bestTotal || (rec.events === bestTotal && maxInWindow > bestWindowCount)) {
      bestTotal = rec.events;
      bestKey = k;
      bestWindowCount = maxInWindow;
      bestWindowStart = winStart;
      bestWindowEnd = winEnd;
    }
  }

  if (!bestKey) return null;

  const rec = countByKey.get(bestKey)!;
  const outboundByIp = new Map<string, number>();
  for (const row of firewall) {
    const src = (row.source_ip ?? '').trim();
    const act = (row.action ?? '').toLowerCase();
    if (src !== rec.ip || act !== 'allow') continue;
    outboundByIp.set(src, (outboundByIp.get(src) ?? 0) + 1);
  }
  const repeatedOutbound = (outboundByIp.get(rec.ip) ?? 0) >= 20;

  let severity = Math.min(100, 25 + Math.floor(rec.events / 3) + Math.min(30, bestWindowCount));
  if (repeatedOutbound) severity = Math.min(100, severity + 20);

  const start = new Date(bestWindowStart || rec.times[0] || 0);
  const end = new Date(bestWindowEnd || start.getTime() + WINDOW_MINUTES * 60 * 1000);

  const highlights: string[] = [
    `Host ${rec.ip} queried ${rec.domain} ${rec.events} times.`,
    `Peak 10-minute window: ${bestWindowCount} queries.`,
  ];
  if (repeatedOutbound) {
    highlights.push(`Same host has repeated allowed outbound firewall connections — possible C2.`);
  }

  const recommended_actions: string[] = [
    `Isolate host IP ${rec.ip}.`,
    `Investigate domain ${rec.domain} and associated destinations.`,
    `Search SIEM for lateral movement from ${rec.ip}.`,
  ];

  const startMs = start.getTime();
  const endMs = end.getTime();
  const related_events = allEvents.filter((e) => {
    const t = e.time.getTime();
    return t >= startMs && t <= endMs;
  });

  return {
    id: 'CASE_B',
    title: 'Beaconing / suspicious DNS repetition',
    severity: Math.round(severity),
    start,
    end,
    primary_entity: rec.ip,
    highlights,
    recommended_actions,
    related_events,
  };
}

/** Increase severity for the incident whose time range is closest to any malware alert; add malware context to highlights. */
function applyMalwareCorrelation(
  incidents: Incident[],
  malware: MalwareAlertRow[]
): void {
  if (malware.length === 0) return;
  const malTimes = malware.map((m) => parseTimestamp(m.timestamp).getTime()).filter((t) => !Number.isNaN(t));
  if (malTimes.length === 0) return;

  const malInfo = malware.map((m) => `${m.hostname}: ${m.threat_name}`).join('; ');

  for (const inc of incidents) {
    inc.highlights.push(`Malware context: ${malInfo}`);
  }

  let minDistA = Infinity;
  let minDistB = Infinity;
  for (const t of malTimes) {
    for (const inc of incidents) {
      const mid = (inc.start.getTime() + inc.end.getTime()) / 2;
      const d = Math.abs(mid - t);
      if (inc.id === 'CASE_A') minDistA = Math.min(minDistA, d);
      else if (inc.id === 'CASE_B') minDistB = Math.min(minDistB, d);
    }
  }

  const closestIsA = minDistA <= minDistB;
  for (const inc of incidents) {
    if (inc.id === 'CASE_A' && closestIsA) inc.severity = Math.min(100, inc.severity + 15);
    if (inc.id === 'CASE_B' && !closestIsA) inc.severity = Math.min(100, inc.severity + 15);
  }
}

/**
 * Build up to 2 incidents (Case A: brute-force, Case B: beaconing) from logs.
 * Applies malware correlation when malware_alerts is non-empty.
 */
export function buildIncidents(
  allEvents: NormalizedEvent[],
  auth: AuthLogRow[],
  dns: DnsLogRow[],
  firewall: FirewallLogRow[],
  malware: MalwareAlertRow[]
): Incident[] {
  const incidents: Incident[] = [];
  const caseA = detectCaseA(auth, allEvents);
  if (caseA) incidents.push(caseA);
  const caseB = detectCaseB(dns, firewall, allEvents);
  if (caseB) incidents.push(caseB);
  applyMalwareCorrelation(incidents, malware);
  return incidents.slice(0, 2);
}

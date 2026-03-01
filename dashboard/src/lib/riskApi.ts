/**
 * Risk scoring API client (backend at localhost:8000 by default).
 * Converts dashboard NormalizedEvent[] to backend event shape and calls /predict and /add-data.
 */
import type { NormalizedEvent } from './types';

const RISK_API_URL =
  (typeof import.meta.env !== 'undefined' && (import.meta.env as Record<string, string>).VITE_RISK_API_URL) ||
  (import.meta.env?.MODE === 'production' ? 'https://uainnovatecybersecurity.onrender.com' : 'http://localhost:8000');

export type RiskResponse = {
  anomalyScore: number;
  message: string;
  coordinatedEscalation: boolean;
  trendSummary: string;
};

/** Map NormalizedEvent to backend event: timestamp (ms), sourceIp, fileSource, severity, rule */
function toBackendEvent(e: NormalizedEvent): Record<string, unknown> {
  const src = e.source;
  const ip = e.entity_ip ?? (e.raw as { source_ip?: string }).source_ip ?? (e.raw as { client_ip?: string }).client_ip ?? (e.raw as { hostname?: string }).hostname ?? '-';
  let severity = 'low';
  let rule = (e as { action?: string }).action ?? '';
  if (src === 'auth') {
    const action = (e.raw as { action?: string }).action ?? '';
    if (action !== 'success' && action !== 'Success') {
      severity = 'high';
      rule = rule || 'auth_fail';
    }
  } else if (src === 'malware') {
    severity = 'critical';
    rule = (e.raw as { threat_name?: string }).threat_name ?? 'malware';
  } else if (src === 'firewall') {
    const action = (e.raw as { action?: string }).action ?? '';
    if (action.toLowerCase().includes('deny') || action.toLowerCase().includes('block')) rule = 'block';
  }
  return {
    timestamp: e.time.getTime(),
    sourceIp: String(ip),
    fileSource: src,
    severity,
    rule,
  };
}

export function toBackendEvents(events: NormalizedEvent[]): Record<string, unknown>[] {
  return events.map(toBackendEvent);
}

export async function fetchPredict(events: Record<string, unknown>[]): Promise<RiskResponse> {
  const res = await fetch(`${RISK_API_URL}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ events }),
  });
  if (!res.ok) throw new Error(`Risk API /predict failed: ${res.status}`);
  return res.json();
}

export async function fetchAddData(events: Record<string, unknown>[]): Promise<void> {
  const res = await fetch(`${RISK_API_URL}/add-data`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ events }),
  });
  if (!res.ok) throw new Error(`Risk API /add-data failed: ${res.status}`);
}

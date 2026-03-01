import { useMemo, useState, useEffect } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
  Brush,
} from 'recharts';
import { format } from 'date-fns';
import type { NormalizedEvent } from '../lib/types';

type Props = {
  events: NormalizedEvent[];
};

/** Count as IP denial only when auth action is "Failed Login" (case-insensitive, extra spaces normalized). */
function isFailedLogin(e: { source: string; action?: string }): boolean {
  const a = (e.action ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
  return e.source === 'auth' && a === 'failed login';
}

type Bucket = {
  minute: string;
  /** Auth events that are NOT failed logins (success, etc.) */
  authSuccess: number;
  dns: number;
  ipDenials: number;
  firewall: number;
  malware: number;
  /** Total events (for brush overview strip) */
  total: number;
};

const COLORS = {
  authSuccess: '#3b82f6',
  dns: '#14b8a6',
  ipDenials: '#ef4444',
  firewall: '#f59e0b',
  malware: '#8b5cf6',
} as const;

// Start 100% zoomed out (show full range)

export function TimelineChart({ events }: Props) {
  const [brushRange, setBrushRange] = useState<{ startIndex: number; endIndex: number } | null>(null);

  const { data, summary } = useMemo(() => {
    const buckets = new Map<string, Bucket>();
    const getKey = (d: Date) => format(d, 'yyyy-MM-dd HH:mm');

    for (const e of events) {
      if (Number.isNaN(e.time.getTime())) continue;
      const key = getKey(e.time);
      let b = buckets.get(key);
      if (!b) {
        b = { minute: key, authSuccess: 0, dns: 0, ipDenials: 0, firewall: 0, malware: 0, total: 0 };
        buckets.set(key, b);
      }
      if (e.source === 'auth') {
        if (isFailedLogin(e)) b.ipDenials += 1;
        else b.authSuccess += 1;
      } else if (e.source === 'dns') b.dns += 1;
      else if (e.source === 'firewall' && (e.action ?? '').toLowerCase() === 'deny') b.firewall += 1;
      else if (e.source === 'malware') b.malware += 1;
    }

    const sorted = Array.from(buckets.values())
      .map((b) => ({ ...b, total: b.authSuccess + b.dns + b.ipDenials + b.firewall + b.malware }))
      .sort((a, b) => a.minute.localeCompare(b.minute));

    // Plain-language summary so the chart "tells you something"
    let summaryText = '';
    if (sorted.length > 0) {
      const totalFailed = sorted.reduce((s, b) => s + b.ipDenials, 0);
      const totalSuccess = sorted.reduce((s, b) => s + b.authSuccess, 0);
      const totalDns = sorted.reduce((s, b) => s + b.dns, 0);
      const totalFw = sorted.reduce((s, b) => s + b.firewall, 0);
      const totalMal = sorted.reduce((s, b) => s + b.malware, 0);
      const peak = sorted.reduce((best, b) => (b.total > best.total ? b : best), sorted[0]);
      const parts: string[] = [];
      if (totalFailed > 0) parts.push(`${totalFailed} failed login${totalFailed !== 1 ? 's' : ''}`);
      if (totalSuccess > 0) parts.push(`${totalSuccess} successful auth`);
      if (totalDns > 0) parts.push(`${totalDns} DNS`);
      if (totalFw > 0) parts.push(`${totalFw} firewall denial${totalFw !== 1 ? 's' : ''}`);
      if (totalMal > 0) parts.push(`${totalMal} malware`);
      const breakdown = parts.length > 0 ? parts.join(', ') : 'no events';
      summaryText = `In this window: ${breakdown}. Peak: ${peak.total} events/min at ${peak.minute}.`;
    }

    return { data: sorted, summary: summaryText };
  }, [events]);

  // Start 100% zoomed out: set full range when data is available or when dataset changes (e.g. reload / new CSV)
  useEffect(() => {
    if (data.length > 0) {
      setBrushRange({ startIndex: 0, endIndex: data.length - 1 });
    } else {
      setBrushRange(null);
    }
  }, [events, data.length]);

  const brushStart = brushRange?.startIndex ?? 0;
  const brushEnd = brushRange?.endIndex ?? Math.max(0, data.length - 1);

  if (data.length === 0) {
    return (
      <div className="timeline-chart">
        <h3>Events per minute</h3>
        <p className="timeline-chart__empty">No events in this incident.</p>
      </div>
    );
  }

  return (
    <div className="timeline-chart">
      <h3>Event intensity over time</h3>
      <p className="timeline-chart__desc">
        Stacked events per minute (no double-count). Red = failed logins; blue = successful auth; teal = DNS; orange = firewall; purple = malware.
      </p>
      {summary && (
        <p className="timeline-chart__summary" role="status">
          {summary}
        </p>
      )}
      <div className="timeline-chart__zoom" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Zoom:</span>
        <button
          type="button"
            onClick={() => setBrushRange((prev) => {
            const start = prev?.startIndex ?? 0;
            const end = prev?.endIndex ?? Math.max(0, data.length - 1);
            const span = end - start + 1;
            const newSpan = Math.max(5, Math.floor(span / 1.5));
            const mid = start + Math.floor(span / 2);
            const newStart = Math.max(0, mid - Math.floor(newSpan / 2));
            const newEnd = Math.min(data.length - 1, newStart + newSpan - 1);
            return { startIndex: newStart, endIndex: newEnd };
          })}
          style={{ padding: '4px 10px', fontSize: 12, cursor: 'pointer' }}
        >
          Zoom in
        </button>
        <button
          type="button"
            onClick={() => setBrushRange((prev) => {
            const start = prev?.startIndex ?? 0;
            const end = prev?.endIndex ?? Math.max(0, data.length - 1);
            const span = end - start + 1;
            const newSpan = Math.min(data.length, Math.ceil(span * 1.5));
            const mid = start + Math.floor(span / 2);
            const newStart = Math.max(0, mid - Math.floor(newSpan / 2));
            const newEnd = Math.min(data.length - 1, newStart + newSpan - 1);
            return { startIndex: newStart, endIndex: newEnd };
          })}
          style={{ padding: '4px 10px', fontSize: 12, cursor: 'pointer' }}
        >
          Zoom out
        </button>
        <button
          type="button"
          onClick={() => data.length > 0 && setBrushRange({ startIndex: 0, endIndex: data.length - 1 })}
          style={{ padding: '4px 10px', fontSize: 12, cursor: 'pointer' }}
        >
          Reset
        </button>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Showing {brushEnd - brushStart + 1} of {data.length} time buckets
        </span>
      </div>
      <ResponsiveContainer width="100%" height={320}>
        <AreaChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <defs>
            <linearGradient id="timeline-auth-success" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COLORS.authSuccess} stopOpacity={0.9} />
              <stop offset="100%" stopColor={COLORS.authSuccess} stopOpacity={0.25} />
            </linearGradient>
            <linearGradient id="timeline-dns" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COLORS.dns} stopOpacity={0.8} />
              <stop offset="100%" stopColor={COLORS.dns} stopOpacity={0.2} />
            </linearGradient>
            <linearGradient id="timeline-ipdenials" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COLORS.ipDenials} stopOpacity={0.95} />
              <stop offset="100%" stopColor={COLORS.ipDenials} stopOpacity={0.35} />
            </linearGradient>
            <linearGradient id="timeline-firewall" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COLORS.firewall} stopOpacity={0.85} />
              <stop offset="100%" stopColor={COLORS.firewall} stopOpacity={0.25} />
            </linearGradient>
            <linearGradient id="timeline-malware" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={COLORS.malware} stopOpacity={0.9} />
              <stop offset="100%" stopColor={COLORS.malware} stopOpacity={0.3} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="minute" tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          <YAxis tick={{ fontSize: 11 }} stroke="var(--text-muted)" label={{ value: 'Events per minute', angle: -90, position: 'insideLeft', style: { fontSize: 11, fill: 'var(--text-muted)' } }} />
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => {
              const bucket = payload?.[0]?.payload as Bucket | undefined;
              return bucket ? `${bucket.minute} — ${bucket.total} total events` : '';
            }}
            formatter={(value: number, name: string) => {
              if (typeof value !== 'number' || value === 0) return [null, name];
              const label = name === 'IP denials' ? 'Failed logins' : name === 'Auth (success)' ? 'Successful auth' : name;
              return [`${value}`, label];
            }}
          />
          <Legend />
          <Area type="monotone" dataKey="authSuccess" stackId="1" stroke={COLORS.authSuccess} fill="url(#timeline-auth-success)" name="Auth (success)" strokeWidth={1.5} />
          <Area type="monotone" dataKey="dns" stackId="1" stroke={COLORS.dns} fill="url(#timeline-dns)" name="DNS events" strokeWidth={1.5} />
          <Area type="monotone" dataKey="firewall" stackId="1" stroke={COLORS.firewall} fill="url(#timeline-firewall)" name="Firewall denials" strokeWidth={1.5} />
          <Area type="monotone" dataKey="ipDenials" stackId="1" stroke={COLORS.ipDenials} fill="url(#timeline-ipdenials)" name="IP denials" strokeWidth={2} />
          <Area type="monotone" dataKey="malware" stackId="1" stroke={COLORS.malware} fill="url(#timeline-malware)" name="Malware" strokeWidth={1.5} />
          {data.length > 1 && (
            <Brush
              dataKey="minute"
              height={36}
              stroke="var(--border)"
              fill="var(--surface)"
              tickFormatter={(value) => String(value).slice(0, 16)}
              startIndex={brushStart}
              endIndex={brushEnd}
              onChange={(next) => {
                if (next && typeof next.startIndex === 'number' && typeof next.endIndex === 'number') {
                  const isFullRange = next.startIndex === 0 && next.endIndex === data.length - 1;
                  const currentlyFull = brushRange === null || (brushRange.startIndex === 0 && brushRange.endIndex === data.length - 1);
                  // Ignore Brush's initial/default narrow range so we stay 100% zoomed out on load
                  if (isFullRange || !currentlyFull) {
                    setBrushRange({ startIndex: next.startIndex, endIndex: next.endIndex });
                  }
                }
              }}
            />
          )}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

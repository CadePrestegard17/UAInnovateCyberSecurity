import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
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
  ipDenials: '#7dd3fc',
  firewall: '#fbbf24',
  malware: '#8b5cf6',
} as const;

const TOOLTIP_LABELS: Record<keyof typeof COLORS, string> = {
  authSuccess: 'Successful auth',
  dns: 'DNS events',
  ipDenials: 'Failed logins',
  firewall: 'Firewall denials',
  malware: 'Malware',
};

const DATA_KEYS = ['authSuccess', 'dns', 'firewall', 'ipDenials', 'malware'] as const;
type DataKey = (typeof DATA_KEYS)[number];

function isDataKey(k: string): k is DataKey {
  return DATA_KEYS.includes(k as DataKey);
}

function TimelineTooltipContent({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ dataKey: string; value?: number; payload: Bucket }>;
  label?: string;
}) {
  if (!active || !payload?.length || !label) return null;
  const bucket = payload[0]?.payload;
  const total = bucket?.total ?? 0;
  return (
    <div
      style={{
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 6,
        padding: '10px 12px',
        boxShadow: '0 2px 8px rgba(0,0,0,0.2)',
      }}
    >
      <div style={{ color: 'var(--text)', marginBottom: 6, fontWeight: 600 }}>
        {label} — {total} total events
      </div>
      {payload.map((entry) => {
        const key = entry.dataKey;
        const color = isDataKey(key) ? COLORS[key] : 'var(--text)';
        const displayLabel = isDataKey(key) ? TOOLTIP_LABELS[key] : key;
        const value = typeof entry.value === 'number' ? entry.value : 0;
        return (
          <div key={key} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, color: color }}>
            <span>{displayLabel} :</span>
            <span>{value}</span>
          </div>
        );
      })}
    </div>
  );
}

// Start 100% zoomed out (show full range)

export function TimelineChart({ events }: Props) {
  const [brushRange, setBrushRange] = useState<{ startIndex: number; endIndex: number } | null>(null);
  const [scrollbarDragging, setScrollbarDragging] = useState(false);
  const scrollbarTrackRef = useRef<HTMLDivElement>(null);
  const dragStartRef = useRef({ brushStart: 0, clientX: 0 });

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
  const span = brushEnd - brushStart + 1;
  const isZoomedIn = span < data.length;

  const handleScrollbarThumbMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      dragStartRef.current = { brushStart, clientX: e.clientX };
      setScrollbarDragging(true);
    },
    [brushStart]
  );

  const handleScrollbarTrackClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target !== e.currentTarget) return;
      const track = scrollbarTrackRef.current;
      if (!track || !isZoomedIn || data.length === 0) return;
      const rect = track.getBoundingClientRect();
      const fraction = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const targetIndex = fraction * (data.length - 1);
      const newStart = Math.max(0, Math.min(data.length - span, Math.round(targetIndex - span / 2)));
      const newEnd = Math.min(data.length - 1, newStart + span - 1);
      setBrushRange({ startIndex: newStart, endIndex: newEnd });
    },
    [data.length, isZoomedIn, span]
  );

  useEffect(() => {
    if (!scrollbarDragging) return;
    const track = scrollbarTrackRef.current;
    const onMove = (e: MouseEvent) => {
      if (!track || data.length === 0) return;
      const rect = track.getBoundingClientRect();
      const trackWidth = rect.width;
      const { brushStart: start0, clientX: x0 } = dragStartRef.current;
      const deltaFraction = (e.clientX - x0) / trackWidth;
      const deltaIndex = Math.round(deltaFraction * data.length);
      const newStart = Math.max(0, Math.min(data.length - span, start0 + deltaIndex));
      const newEnd = Math.min(data.length - 1, newStart + span - 1);
      setBrushRange({ startIndex: newStart, endIndex: newEnd });
    };
    const onUp = () => setScrollbarDragging(false);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [scrollbarDragging, data.length, span]);

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
        Stacked events per minute (no double-count). Light blue = failed logins; blue = successful auth; teal = DNS; orange-yellow = firewall; purple = malware.
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
        {(brushEnd - brushStart + 1) < data.length && (
          <>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Scroll:</span>
            <button
              type="button"
              disabled={brushStart <= 0}
              onClick={() =>
                setBrushRange((prev) => {
                  const start = prev?.startIndex ?? 0;
                  const end = prev?.endIndex ?? Math.max(0, data.length - 1);
                  const span = end - start + 1;
                  const step = Math.max(1, Math.floor(span * 0.25));
                  const newStart = Math.max(0, start - step);
                  const newEnd = Math.min(data.length - 1, newStart + span - 1);
                  return { startIndex: newStart, endIndex: newEnd };
                })
              }
              style={{ padding: '4px 10px', fontSize: 12, cursor: brushStart <= 0 ? 'not-allowed' : 'pointer', opacity: brushStart <= 0 ? 0.6 : 1 }}
            >
              ← Earlier
            </button>
            <button
              type="button"
              disabled={brushEnd >= data.length - 1}
              onClick={() =>
                setBrushRange((prev) => {
                  const start = prev?.startIndex ?? 0;
                  const end = prev?.endIndex ?? Math.max(0, data.length - 1);
                  const span = end - start + 1;
                  const step = Math.max(1, Math.floor(span * 0.25));
                  const newEnd = Math.min(data.length - 1, end + step);
                  const newStart = Math.max(0, newEnd - span + 1);
                  return { startIndex: newStart, endIndex: newEnd };
                })
              }
              style={{ padding: '4px 10px', fontSize: 12, cursor: brushEnd >= data.length - 1 ? 'not-allowed' : 'pointer', opacity: brushEnd >= data.length - 1 ? 0.6 : 1 }}
            >
              Later →
            </button>
          </>
        )}
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Showing {brushEnd - brushStart + 1} of {data.length} time buckets
        </span>
      </div>
      {isZoomedIn && data.length > 0 && (
        <div
          ref={scrollbarTrackRef}
          role="scrollbar"
          aria-valuenow={brushStart}
          aria-valuemin={0}
          aria-valuemax={data.length - 1}
          aria-label="Timeline position"
          onClick={handleScrollbarTrackClick}
          style={{
            height: 20,
            marginBottom: 8,
            background: 'var(--border)',
            borderRadius: 4,
            position: 'relative',
            cursor: 'pointer',
          }}
        >
          <div
            onMouseDown={handleScrollbarThumbMouseDown}
            style={{
              position: 'absolute',
              left: `${(brushStart / data.length) * 100}%`,
              width: `${(span / data.length) * 100}%`,
              top: 2,
              bottom: 2,
              minWidth: 24,
              background: 'var(--text-muted)',
              borderRadius: 3,
              cursor: scrollbarDragging ? 'grabbing' : 'grab',
              pointerEvents: 'auto',
            }}
          />
        </div>
      )}
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
          <Tooltip content={<TimelineTooltipContent />} />
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

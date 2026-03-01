import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
  ReferenceArea,
} from 'recharts';
import { format } from 'date-fns';
import type { NormalizedEvent } from '../lib/types';

const BUCKET_MINUTES = 10;
const SPIKE_THRESHOLD_STD = 2;

const COLORS = {
  auth: '#3b82f6',
  dns: '#14b8a6',
  ipDenials: '#22d3ee',
  firewall: '#f59e0b',
  malware: '#8b5cf6',
} as const;

const SERIES: Array<{ key: 'auth' | 'dns' | 'ipDenials' | 'firewall' | 'malware'; name: string }> = [
  { key: 'auth', name: 'Auth' },
  { key: 'dns', name: 'DNS events' },
  { key: 'ipDenials', name: 'IP denials' },
  { key: 'firewall', name: 'Firewall denials' },
  { key: 'malware', name: 'Malware' },
];

function isFirewallDenial(e: NormalizedEvent): boolean {
  return e.source === 'firewall' && (e.action ?? '').toLowerCase() === 'deny';
}

/** Count as IP denial only when auth action is "Failed Login" (case-insensitive, extra spaces normalized). */
function isFailedLogin(e: NormalizedEvent): boolean {
  const a = (e.action ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
  return e.source === 'auth' && a === 'failed login';
}

type Props = {
  events: NormalizedEvent[];
};

const MALWARE_DISPLAY_OFFSET = 1.5; // draw malware line at 1.5 when value is 0 so it sits above firewall; tooltip still shows actual value
const IP_DENIALS_DISPLAY_OFFSET = 0.5; // draw IP denials line slightly above 0 so it's visible when count is 0; tooltip shows actual value
// Start 100% zoomed out (show full range)

type Bucket = {
  index: number;
  timeKey: string;
  timeLabel: string;
  auth: number;
  dns: number;
  ipDenials: number;
  ipDenialsOffset: number; // ipDenials + IP_DENIALS_DISPLAY_OFFSET for display only
  firewall: number;
  malware: number;
  malwareOffset: number; // malware + MALWARE_DISPLAY_OFFSET for display only
  authSpike: boolean;
  dnsSpike: boolean;
  ipDenialsSpike: boolean;
  firewallSpike: boolean;
  malwareSpike: boolean;
};

function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function std(arr: number[], m?: number): number {
  if (arr.length < 2) return 0;
  const avg = m ?? mean(arr);
  const sqDiffs = arr.map((v) => (v - avg) ** 2);
  return Math.sqrt(sqDiffs.reduce((a, b) => a + b, 0) / arr.length);
}

export function TimeCorrelationChart({ events }: Props) {
  const [brushRange, setBrushRange] = useState<{ startIndex: number; endIndex: number } | null>(null);
  const [scrollbarDragging, setScrollbarDragging] = useState(false);
  const scrollbarTrackRef = useRef<HTMLDivElement>(null);
  const dragStartRef = useRef({ brushStart: 0, clientX: 0 });

  const { data, safeRanges, unsafeRanges } = useMemo(() => {
    const bucketMs = BUCKET_MINUTES * 60 * 1000;
    const buckets = new Map<number, Omit<Bucket, 'authSpike' | 'dnsSpike' | 'ipDenialsSpike' | 'firewallSpike' | 'malwareSpike' | 'index' | 'ipDenialsOffset'>>();

    for (const e of events) {
      if (Number.isNaN(e.time.getTime())) continue;
      const t = e.time.getTime();
      const key = Math.floor(t / bucketMs) * bucketMs;
      let b = buckets.get(key);
      if (!b) {
        b = {
          timeKey: format(key, 'yyyy-MM-dd HH:mm'),
          timeLabel: format(key, 'MM/dd HH:mm'),
          auth: 0,
          dns: 0,
          ipDenials: 0,
          firewall: 0,
          malware: 0,
          malwareOffset: 0,
        };
        buckets.set(key, b);
      }
      if (e.source === 'auth') {
        b!.auth += 1;
        if (isFailedLogin(e)) b!.ipDenials += 1;
      } else if (e.source === 'dns') b!.dns += 1;
      else if (isFirewallDenial(e)) b!.firewall += 1;
      else if (e.source === 'malware') b!.malware += 1;
    }

    const list = Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([, b], i) => ({ ...b, index: i }));

    const authVals = list.map((x) => x.auth);
    const dnsVals = list.map((x) => x.dns);
    const ipDenialsVals = list.map((x) => x.ipDenials);
    const firewallVals = list.map((x) => x.firewall);
    const malwareVals = list.map((x) => x.malware);

    const thresh = (vals: number[]) => {
      const m = mean(vals);
      const s = std(vals, m);
      return s > 0 ? m + SPIKE_THRESHOLD_STD * s : (m > 0 ? m + 1 : 1);
    };

    const dataWithSpikes: Bucket[] = list.map((b) => ({
      ...b,
      index: b.index,
      ipDenialsOffset: b.ipDenials + IP_DENIALS_DISPLAY_OFFSET,
      malwareOffset: b.malware + MALWARE_DISPLAY_OFFSET,
      authSpike: b.auth >= thresh(authVals),
      dnsSpike: b.dns >= thresh(dnsVals),
      ipDenialsSpike: b.ipDenials >= thresh(ipDenialsVals),
      firewallSpike: b.firewall >= thresh(firewallVals),
      malwareSpike: b.malware >= thresh(malwareVals),
    }));

    // Safe = green. Unsafe = red. Every bucket is one or the other (no blank).
    const safeRanges: { start: number; end: number }[] = [];
    const unsafeRanges: { start: number; end: number }[] = [];
    let i = 0;
    const isSafe = (b: Bucket) =>
      b.malware === 0 &&
      !b.authSpike &&
      !b.dnsSpike &&
      !b.ipDenialsSpike &&
      !b.firewallSpike &&
      !b.malwareSpike;
    i = 0;
    while (i < dataWithSpikes.length) {
      const safe = isSafe(dataWithSpikes[i]);
      const start = i;
      while (i < dataWithSpikes.length && isSafe(dataWithSpikes[i]) === safe) {
        i++;
      }
      if (safe) safeRanges.push({ start, end: i - 1 });
      else unsafeRanges.push({ start, end: i - 1 });
    }

    return { data: dataWithSpikes, safeRanges, unsafeRanges };
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
  const isZoomedIn = data.length > 0 && span < data.length;
  const zoomedData = useMemo(() => data.slice(brushStart, brushEnd + 1), [data, brushStart, brushEnd]);

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
      const { brushStart: start0, clientX: x0 } = dragStartRef.current;
      const deltaFraction = (e.clientX - x0) / rect.width;
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

  // Reference areas in zoomed view: only show ranges that overlap [brushStart, brushEnd], rebased to zoomed indices
  const zoomedSafeRanges = useMemo(
    () =>
      safeRanges
        .map((r) => ({ start: Math.max(r.start, brushStart) - brushStart, end: Math.min(r.end, brushEnd) - brushStart }))
        .filter((r) => r.start <= r.end),
    [safeRanges, brushStart, brushEnd]
  );
  const zoomedUnsafeRanges = useMemo(
    () =>
      unsafeRanges
        .map((r) => ({ start: Math.max(r.start, brushStart) - brushStart, end: Math.min(r.end, brushEnd) - brushStart }))
        .filter((r) => r.start <= r.end),
    [unsafeRanges, brushStart, brushEnd]
  );

  if (data.length === 0) {
    return (
      <div className="time-correlation">
        <h3>Correlation: Time</h3>
        <p className="time-correlation__empty">No events to show.</p>
      </div>
    );
  }

  const SPIKE_DOT_COLOR = '#dc2626';
  const IP_DENIALS_SPIKE_DOT_COLOR = '#f59e0b';

  const renderDot =
    (spikeKey: keyof Pick<Bucket, 'authSpike' | 'dnsSpike' | 'ipDenialsSpike' | 'firewallSpike' | 'malwareSpike'>, seriesKey?: 'auth' | 'dns' | 'ipDenials' | 'firewall' | 'malware') =>
    (props: { cx?: number; cy?: number; payload?: Bucket }) => {
      const { cx, cy, payload } = props;
      if (cx == null || cy == null || !payload) return null;
      if (!payload[spikeKey]) return null;
      const color = seriesKey === 'ipDenials' ? IP_DENIALS_SPIKE_DOT_COLOR : SPIKE_DOT_COLOR;
      return (
        <circle cx={cx} cy={cy} r={5} fill={color} stroke={color} strokeWidth={2} />
      );
    };

  return (
    <div className="time-correlation">
      <h3>Correlation: Time</h3>
      <p className="time-correlation__legend-desc">
        Five lines: Auth, DNS events, IP denials, Firewall denials, Malware. Y-axis = count.
      </p>
      <div className="time-correlation__zoom" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Zoom:</span>
        <button
          type="button"
          onClick={() =>
            setBrushRange((prev) => {
              const start = prev?.startIndex ?? 0;
              const end = prev?.endIndex ?? Math.max(0, data.length - 1);
              const span = end - start + 1;
              const newSpan = Math.max(3, Math.floor(span / 1.5));
              const mid = start + Math.floor(span / 2);
              const newStart = Math.max(0, mid - Math.floor(newSpan / 2));
              const newEnd = Math.min(data.length - 1, newStart + newSpan - 1);
              return { startIndex: newStart, endIndex: newEnd };
            })
          }
          style={{ padding: '4px 10px', fontSize: 12, cursor: 'pointer' }}
        >
          Zoom in
        </button>
        <button
          type="button"
          onClick={() =>
            setBrushRange((prev) => {
              const start = prev?.startIndex ?? 0;
              const end = prev?.endIndex ?? Math.max(0, data.length - 1);
              const span = end - start + 1;
              const newSpan = Math.min(data.length, Math.ceil(span * 1.5));
              const mid = start + Math.floor(span / 2);
              const newStart = Math.max(0, mid - Math.floor(newSpan / 2));
              const newEnd = Math.min(data.length - 1, newStart + newSpan - 1);
              return { startIndex: newStart, endIndex: newEnd };
            })
          }
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
          Showing {brushEnd - brushStart + 1} of {data.length} buckets
        </span>
      </div>
      {isZoomedIn && (
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
      <div className="time-correlation__legend">
        {SERIES.map(({ key, name }) => (
          <span key={key} className="time-correlation__legend-item" style={{ color: COLORS[key] }}>
            ● {name}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={zoomedData} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis
            dataKey="index"
            type="number"
            domain={[(zoomedData[0]?.index ?? 0) - 0.5, (zoomedData[zoomedData.length - 1]?.index ?? 0) + 0.5]}
            tick={{ fontSize: 10 }}
            stroke="var(--text-muted)"
            interval="preserveStartEnd"
            tickFormatter={(val) => zoomedData.find((d) => d.index === Number(val))?.timeLabel ?? ''}
          />
          <YAxis tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => (payload?.[0]?.payload as Bucket | undefined)?.timeLabel ?? ''}
            formatter={(value: number | undefined, name: string | undefined, item: { payload?: Bucket }) => {
              const p = item?.payload as Bucket | undefined;
              const actual = name === 'Malware' ? p?.malware : name === 'IP denials' ? p?.ipDenials ?? 0 : (value ?? 0);
              const label = name === 'IP denials' ? 'denials' : 'events';
              return [`${actual} ${label}`, name ?? ''];
            }}
          />
          {zoomedSafeRanges.map((r, idx) => (
            <ReferenceArea
              key={`safe-${idx}`}
              x1={zoomedData[r.start]?.index ?? r.start - 0.5}
              x2={(zoomedData[r.end]?.index ?? r.end) + 0.5}
              fill="#22c55e"
              fillOpacity={0.12}
            />
          ))}
          {zoomedUnsafeRanges.map((r, idx) => (
            <ReferenceArea
              key={`unsafe-${idx}`}
              x1={zoomedData[r.start]?.index ?? r.start - 0.5}
              x2={(zoomedData[r.end]?.index ?? r.end) + 0.5}
              fill={idx === 1 ? '#f59e0b' : '#dc2626'}
              fillOpacity={0.2}
            />
          ))}
          {SERIES.map(({ key, name }) => (
            <Line
              key={key}
              type="monotone"
              dataKey={key === 'malware' ? 'malwareOffset' : key === 'ipDenials' ? 'ipDenialsOffset' : key}
              name={name}
              stroke={COLORS[key]}
              strokeWidth={2}
              dot={renderDot(`${key}Spike` as keyof Pick<Bucket, 'authSpike' | 'dnsSpike' | 'ipDenialsSpike' | 'firewallSpike' | 'malwareSpike'>, key)}
              connectNulls
            />
          ))}
          <Legend
            wrapperStyle={{ paddingTop: '8px' }}
            formatter={(value) => <span style={{ color: 'var(--text)' }}>{value}</span>}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

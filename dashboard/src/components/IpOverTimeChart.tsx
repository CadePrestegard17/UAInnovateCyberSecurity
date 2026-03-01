import { useMemo, useState, useEffect } from 'react';
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
const TOP_IP_COUNT = 10;
const SPIKE_THRESHOLD_STD = 2;
// Start 100% zoomed out (show full range)

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

const IP_DENIALS_COLOR = '#ef4444';

// Distinct colors for up to 12 IPs; alarming IP will use red override
const IP_COLORS = [
  '#3b82f6',
  '#22d3ee',
  '#f59e0b',
  '#8b5cf6',
  '#ec4899',
  '#14b8a6',
  '#f97316',
  '#6366f1',
  '#84cc16',
  '#a855f7',
];

type Props = {
  events: NormalizedEvent[];
};

export function IpOverTimeChart({ events }: Props) {
  const [brushRange, setBrushRange] = useState<{ startIndex: number; endIndex: number } | null>(null);

  const { data, topIps, safeRanges, allUnsafe, debug } = useMemo(() => {
    const bucketMs = BUCKET_MINUTES * 60 * 1000;
    const totalByIp = new Map<string, number>();
    /** Count as IP denial only when auth action is "Failed Login" (case-insensitive, extra spaces normalized). */
    function isFailedLogin(ev: { source: string; action?: string }): boolean {
      const a = (ev.action ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
      return ev.source === 'auth' && a === 'failed login';
    }
    type BucketRow = { auth: number; dns: number; ipDenials: number; firewall: number; malware: number; ipCounts: Map<string, number> };
    const bucketByTime = new Map<number, BucketRow>();

    for (const e of events) {
      if (Number.isNaN(e.time.getTime())) continue;
      const t = e.time.getTime();
      const key = Math.floor(t / bucketMs) * bucketMs;
      let b = bucketByTime.get(key);
      if (!b) {
        b = { auth: 0, dns: 0, ipDenials: 0, firewall: 0, malware: 0, ipCounts: new Map() };
        bucketByTime.set(key, b);
      }
      if (e.source === 'auth') {
        b.auth += 1;
        if (isFailedLogin(e)) b.ipDenials += 1;
      } else if (e.source === 'dns') b.dns += 1;
      else if (e.source === 'firewall' && (e.action ?? '').toLowerCase() === 'deny') b.firewall += 1;
      else if (e.source === 'malware') b.malware += 1;
      const ip = e.entity_ip?.trim();
      if (ip) {
        totalByIp.set(ip, (totalByIp.get(ip) ?? 0) + 1);
        b.ipCounts.set(ip, (b.ipCounts.get(ip) ?? 0) + 1);
      }
    }

    const sortedIps = Array.from(totalByIp.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, TOP_IP_COUNT)
      .map(([ip]) => ip);

    const timeKeys = Array.from(bucketByTime.keys()).sort((a, b) => a - b);
    const list = timeKeys.map((key) => bucketByTime.get(key)!);
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
    const isSafe = (b: BucketRow) => {
      const authSpike = b.auth >= thresh(authVals);
      const dnsSpike = b.dns >= thresh(dnsVals);
      const ipDenialsSpike = b.ipDenials >= thresh(ipDenialsVals);
      const firewallSpike = b.firewall >= thresh(firewallVals);
      const malwareSpike = b.malware >= thresh(malwareVals);
      return b.malware === 0 && !authSpike && !dnsSpike && !ipDenialsSpike && !firewallSpike && !malwareSpike;
    };
    const isFirewallDominant = (b: BucketRow) => {
      const firewallSpike = b.firewall >= thresh(firewallVals);
      return !isSafe(b) && firewallSpike && b.malware === 0;
    };
    const getBucketType = (b: BucketRow): 'safe' | 'firewall' | 'other' => {
      if (isSafe(b)) return 'safe';
      if (isFirewallDominant(b)) return 'firewall';
      return 'other';
    };

    const safeRanges: { start: number; end: number }[] = [];
    const firewallRanges: { start: number; end: number }[] = [];
    const otherUnsafeRanges: { start: number; end: number }[] = [];
    let i = 0;
    while (i < list.length) {
      const typ = getBucketType(list[i]);
      const start = i;
      while (i < list.length && getBucketType(list[i]) === typ) i++;
      if (typ === 'safe') safeRanges.push({ start, end: i - 1 });
      else if (typ === 'firewall') firewallRanges.push({ start, end: i - 1 });
      else otherUnsafeRanges.push({ start, end: i - 1 });
    }

    const data = timeKeys.map((key, index) => {
      const b = bucketByTime.get(key)!;
      const row: Record<string, string | number> = {
        index,
        timeKey: format(key, 'yyyy-MM-dd HH:mm'),
        timeLabel: format(key, 'MM/dd HH:mm'),
        ipDenials: b.ipDenials,
      };
      for (const ip of sortedIps) {
        row[ip] = b.ipCounts.get(ip) ?? 0;
      }
      return row;
    });

    const allUnsafe = [...firewallRanges, ...otherUnsafeRanges].sort((a, b) => a.start - b.start);

    // Debug: verify IP Denials data for troubleshooting
    const totalIpDenials = list.reduce((sum, b) => sum + b.ipDenials, 0);
    const bucketsWithIpDenials = list.filter((b) => b.ipDenials > 0).length;
    const sampleIpDenials = data.slice(0, 5).map((row) => row.ipDenials);
    const authFailedLoginCount = events.filter((e) => e.source === 'auth' && (e.action ?? '').replace(/\s+/g, ' ').trim().toLowerCase() === 'failed login').length;
    const keyCollision = sortedIps.includes('ipDenials');
    const debug = {
      eventCount: events.length,
      authFailedLoginCount,
      totalIpDenials,
      bucketsWithIpDenials,
      bucketCount: list.length,
      sampleIpDenials,
      firstDataRow: data[0] ? { ipDenials: data[0].ipDenials, timeLabel: data[0].timeLabel } : null,
      keyCollision: keyCollision ? 'WARNING: an IP is named "ipDenials" and overwrites the series' : false,
    };
    if (typeof console !== 'undefined' && console.debug) {
      console.debug('[IpOverTimeChart] IP Denials debug', debug);
    }

    return { data, topIps: sortedIps, safeRanges, allUnsafe, debug };
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
  const zoomedData = useMemo(() => data.slice(brushStart, brushEnd + 1), [data, brushStart, brushEnd]);

  const zoomedSafeRanges = useMemo(
    () =>
      safeRanges
        .map((r) => ({ start: Math.max(r.start, brushStart) - brushStart, end: Math.min(r.end, brushEnd) - brushStart }))
        .filter((r) => r.start <= r.end),
    [safeRanges, brushStart, brushEnd]
  );
  const zoomedUnsafeRanges = useMemo(
    () =>
      allUnsafe
        .map((r) => ({ start: Math.max(r.start, brushStart) - brushStart, end: Math.min(r.end, brushEnd) - brushStart }))
        .filter((r) => r.start <= r.end),
    [allUnsafe, brushStart, brushEnd]
  );

  if (data.length === 0 || topIps.length === 0) {
    return (
      <div className="ip-over-time">
        <h3>IP addresses over time</h3>
        <p className="ip-over-time__empty">No IP activity to show.</p>
      </div>
    );
  }

  return (
    <div className="ip-over-time">
      <h3>IP addresses over time</h3>
      {debug && (
        <details className="ip-over-time__debug" style={{ marginBottom: 8, fontSize: 12, color: 'var(--text-muted)' }}>
          <summary>Debug: IP Denials data</summary>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(debug, null, 2)}
          </pre>
          <p style={{ margin: '4px 0 0 0' }}>
            If <code>authFailedLoginCount</code> or <code>totalIpDenials</code> is 0, failed logins aren’t in the data or aren’t matching. If they’re &gt; 0 but the line still doesn’t show, the issue is likely Recharts (e.g. scale or draw order).
          </p>
        </details>
      )}
      <p className="ip-over-time__legend-desc">
        Event count per time bucket (10 min) for top {topIps.length} IPs and IP Denials.
      </p>
      <div className="ip-over-time__zoom" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
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
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Showing {brushEnd - brushStart + 1} of {data.length} buckets
        </span>
      </div>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={zoomedData} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis
            dataKey="index"
            type="number"
            domain={[(zoomedData[0]?.index as number ?? 0) - 0.5, (zoomedData[zoomedData.length - 1]?.index as number ?? 0) + 0.5]}
            tick={{ fontSize: 10 }}
            stroke="var(--text-muted)"
            interval="preserveStartEnd"
            tickFormatter={(val) => String(zoomedData.find((d) => d.index === Number(val))?.timeLabel ?? '')}
          />
          <YAxis tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          {zoomedSafeRanges.map((r, idx) => (
            <ReferenceArea
              key={`safe-${idx}`}
              x1={(zoomedData[r.start]?.index as number ?? r.start) - 0.5}
              x2={(zoomedData[r.end]?.index as number ?? r.end) + 0.5}
              fill="#22c55e"
              fillOpacity={0.12}
            />
          ))}
          {zoomedUnsafeRanges.map((r, idx) => (
            <ReferenceArea
              key={`unsafe-${idx}`}
              x1={(zoomedData[r.start]?.index as number ?? r.start) - 0.5}
              x2={(zoomedData[r.end]?.index as number ?? r.end) + 0.5}
              fill={idx === 1 ? '#f59e0b' : '#dc2626'}
              fillOpacity={0.2}
            />
          ))}
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => String((payload?.[0]?.payload as Record<string, unknown>)?.timeLabel ?? '')}
            formatter={(value: number | undefined, name: string | undefined) =>
              name === 'IP Denials'
                ? [`${value ?? 0} failed logins`, name]
                : [`${value ?? 0} events`, name ?? '']}
          />
          <Legend
            wrapperStyle={{ paddingTop: '8px' }}
            formatter={(value) => <span style={{ color: 'var(--text)' }}>{value}</span>}
          />
          {topIps.map((ip, i) => (
            <Line
              key={ip}
              type="monotone"
              dataKey={ip}
              name={ip}
              stroke={ip === '185.19.20.21' ? '#dc2626' : IP_COLORS[i % IP_COLORS.length]}
              strokeWidth={ip === '185.19.20.21' ? 2.5 : 2}
              dot={false}
              connectNulls
            />
          ))}
          <Line
            key="ip-denials"
            type="monotone"
            dataKey="ipDenials"
            name="IP Denials"
            stroke={IP_DENIALS_COLOR}
            strokeWidth={2.5}
            strokeDasharray="6 4"
            dot={false}
            connectNulls
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

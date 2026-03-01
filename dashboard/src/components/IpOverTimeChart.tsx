import { useMemo } from 'react';
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
  const { data, topIps, safeRanges, allUnsafe } = useMemo(() => {
    const bucketMs = BUCKET_MINUTES * 60 * 1000;
    const totalByIp = new Map<string, number>();
    type BucketRow = { auth: number; dns: number; firewall: number; malware: number; ipCounts: Map<string, number> };
    const bucketByTime = new Map<number, BucketRow>();

    for (const e of events) {
      if (Number.isNaN(e.time.getTime())) continue;
      const t = e.time.getTime();
      const key = Math.floor(t / bucketMs) * bucketMs;
      let b = bucketByTime.get(key);
      if (!b) {
        b = { auth: 0, dns: 0, firewall: 0, malware: 0, ipCounts: new Map() };
        bucketByTime.set(key, b);
      }
      if (e.source === 'auth') b.auth += 1;
      else if (e.source === 'dns') b.dns += 1;
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
      const firewallSpike = b.firewall >= thresh(firewallVals);
      const malwareSpike = b.malware >= thresh(malwareVals);
      return b.malware === 0 && !authSpike && !dnsSpike && !firewallSpike && !malwareSpike;
    };
    const isFirewallDominant = (b: BucketRow) => {
      const authSpike = b.auth >= thresh(authVals);
      const dnsSpike = b.dns >= thresh(dnsVals);
      const firewallSpike = b.firewall >= thresh(firewallVals);
      const malwareSpike = b.malware >= thresh(malwareVals);
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
      };
      for (const ip of sortedIps) {
        row[ip] = b.ipCounts.get(ip) ?? 0;
      }
      return row;
    });

    const allUnsafe = [...firewallRanges, ...otherUnsafeRanges].sort((a, b) => a.start - b.start);
    return { data, topIps: sortedIps, safeRanges, allUnsafe };
  }, [events]);

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
      <p className="ip-over-time__legend-desc">
        Event count per time bucket (10 min) for top {topIps.length} IPs. Green = good. First suspicious block = red, second = orange.
      </p>
      <ResponsiveContainer width="100%" height={320}>
        <LineChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis
            dataKey="index"
            type="number"
            domain={[-0.5, data.length - 0.5]}
            tick={{ fontSize: 10 }}
            stroke="var(--text-muted)"
            interval="preserveStartEnd"
            tickFormatter={(val) => data[Number(val)]?.timeLabel ?? ''}
          />
          <YAxis tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          {safeRanges.map((r, idx) => (
            <ReferenceArea
              key={`safe-${idx}`}
              x1={r.start - 0.5}
              x2={r.end + 0.5}
              fill="#22c55e"
              fillOpacity={0.12}
            />
          ))}
          {allUnsafe.map((r, idx) => (
            <ReferenceArea
              key={`unsafe-${idx}`}
              x1={r.start - 0.5}
              x2={r.end + 0.5}
              fill={idx === 1 ? '#f59e0b' : '#dc2626'}
              fillOpacity={0.2}
            />
          ))}
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => (payload?.[0]?.payload as Record<string, unknown>)?.timeLabel ?? ''}
            formatter={(value: number, name: string) => [`${value} events`, name]}
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
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

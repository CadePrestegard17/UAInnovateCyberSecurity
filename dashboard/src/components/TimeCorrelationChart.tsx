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
const SPIKE_THRESHOLD_STD = 2;

const COLORS = {
  auth: '#3b82f6',
  dns: '#22d3ee',
  firewall: '#f59e0b',
  malware: '#8b5cf6',
} as const;

const SERIES: Array<{ key: 'auth' | 'dns' | 'firewall' | 'malware'; name: string }> = [
  { key: 'auth', name: 'Auth' },
  { key: 'dns', name: 'DNS events' },
  { key: 'firewall', name: 'Firewall denials' },
  { key: 'malware', name: 'Malware' },
];

function isFirewallDenial(e: NormalizedEvent): boolean {
  return e.source === 'firewall' && (e.action ?? '').toLowerCase() === 'deny';
}

type Props = {
  events: NormalizedEvent[];
};

const MALWARE_DISPLAY_OFFSET = 1.5; // draw malware line at 1.5 when value is 0 so it sits above firewall; tooltip still shows actual value

type Bucket = {
  index: number;
  timeKey: string;
  timeLabel: string;
  auth: number;
  dns: number;
  firewall: number;
  malware: number;
  malwareOffset: number; // malware + MALWARE_DISPLAY_OFFSET for display only
  authSpike: boolean;
  dnsSpike: boolean;
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
  const { data, spikeRanges, safeRanges, unsafeRanges } = useMemo(() => {
    const bucketMs = BUCKET_MINUTES * 60 * 1000;
    const buckets = new Map<number, Omit<Bucket, 'authSpike' | 'dnsSpike' | 'firewallSpike' | 'malwareSpike' | 'index'>>();

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
          firewall: 0,
          malware: 0,
        };
        buckets.set(key, b);
      }
      if (e.source === 'auth') b.auth += 1;
      else if (e.source === 'dns') b.dns += 1;
      else if (isFirewallDenial(e)) b.firewall += 1;
      else if (e.source === 'malware') b.malware += 1;
    }

    const list = Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([, b], i) => ({ ...b, index: i }));

    const authVals = list.map((x) => x.auth);
    const dnsVals = list.map((x) => x.dns);
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
      malwareOffset: b.malware + MALWARE_DISPLAY_OFFSET,
      authSpike: b.auth >= thresh(authVals),
      dnsSpike: b.dns >= thresh(dnsVals),
      firewallSpike: b.firewall >= thresh(firewallVals),
      malwareSpike: b.malware >= thresh(malwareVals),
    }));

    const ranges: { start: number; end: number }[] = [];
    let i = 0;
    while (i < dataWithSpikes.length) {
      const hasSpike =
        dataWithSpikes[i].authSpike ||
        dataWithSpikes[i].dnsSpike ||
        dataWithSpikes[i].firewallSpike ||
        dataWithSpikes[i].malwareSpike;
      if (hasSpike) {
        const start = i;
        while (
          i < dataWithSpikes.length &&
          (dataWithSpikes[i].authSpike ||
            dataWithSpikes[i].dnsSpike ||
            dataWithSpikes[i].firewallSpike ||
            dataWithSpikes[i].malwareSpike)
        ) {
          i++;
        }
        ranges.push({ start, end: i - 1 });
      } else {
        i++;
      }
    }

    // Safe = green. Unsafe = red. Every bucket is one or the other (no blank).
    const safeRanges: { start: number; end: number }[] = [];
    const unsafeRanges: { start: number; end: number }[] = [];
    const isSafe = (b: Bucket) =>
      b.malware === 0 &&
      !b.authSpike &&
      !b.dnsSpike &&
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

    return { data: dataWithSpikes, spikeRanges: ranges, safeRanges, unsafeRanges };
  }, [events]);

  if (data.length === 0) {
    return (
      <div className="time-correlation">
        <h3>Correlation: Time</h3>
        <p className="time-correlation__empty">No events to show.</p>
      </div>
    );
  }

  const SPIKE_DOT_COLOR = '#dc2626';
  const DNS_SPIKE_DOT_COLOR = '#f59e0b';

  const renderDot =
    (spikeKey: keyof Pick<Bucket, 'authSpike' | 'dnsSpike' | 'firewallSpike' | 'malwareSpike'>, seriesKey?: 'auth' | 'dns' | 'firewall' | 'malware') =>
    (props: { cx?: number; cy?: number; payload?: Bucket }) => {
      const { cx, cy, payload } = props;
      if (cx == null || cy == null || !payload) return null;
      if (!payload[spikeKey]) return null;
      const color = seriesKey === 'dns' ? DNS_SPIKE_DOT_COLOR : SPIKE_DOT_COLOR;
      return (
        <circle cx={cx} cy={cy} r={5} fill={color} stroke={color} strokeWidth={2} />
      );
    };

  return (
    <div className="time-correlation">
      <h3>Correlation: Time</h3>
      <p className="time-correlation__legend-desc">
        Four lines: Auth, DNS events, Firewall denials, Malware. Y-axis = count. Green = good. First suspicious block = red, second = orange. Red dot = spike (orange on DNS).
      </p>
      <div className="time-correlation__legend">
        {SERIES.map(({ key, name }) => (
          <span key={key} className="time-correlation__legend-item" style={{ color: COLORS[key] }}>
            ● {name}
          </span>
        ))}
      </div>
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
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => (payload?.[0]?.payload as Bucket | undefined)?.timeLabel ?? ''}
            formatter={(value: number, name: string, item: { payload?: Bucket }) => {
              const actual = name === 'Malware' ? (item?.payload as Bucket)?.malware : value;
              return [`${actual ?? 0} events`, name];
            }}
          />
          {safeRanges.map((r, idx) => (
            <ReferenceArea
              key={`safe-${idx}`}
              x1={r.start - 0.5}
              x2={r.end + 0.5}
              fill="#22c55e"
              fillOpacity={0.12}
            />
          ))}
          {unsafeRanges.map((r, idx) => (
            <ReferenceArea
              key={`unsafe-${idx}`}
              x1={r.start - 0.5}
              x2={r.end + 0.5}
              fill={idx === 1 ? '#f59e0b' : '#dc2626'}
              fillOpacity={0.2}
            />
          ))}
          {SERIES.map(({ key, name }) => (
            <Line
              key={key}
              type="monotone"
              dataKey={key === 'malware' ? 'malwareOffset' : key}
              name={name}
              stroke={COLORS[key]}
              strokeWidth={2}
              dot={renderDot(`${key}Spike` as keyof Pick<Bucket, 'authSpike' | 'dnsSpike' | 'firewallSpike' | 'malwareSpike'>, key)}
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

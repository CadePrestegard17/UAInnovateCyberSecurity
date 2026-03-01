import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
  CartesianGrid,
} from 'recharts';
import { format } from 'date-fns';
import type { NormalizedEvent } from '../lib/types';

type Props = {
  events: NormalizedEvent[];
};

type Bucket = {
  minute: string;
  auth: number;
  dns: number;
  firewall: number;
  malware: number;
};

export function TimelineChart({ events }: Props) {
  const data = useMemo(() => {
    const buckets = new Map<string, Bucket>();
    const getKey = (d: Date) => format(d, 'yyyy-MM-dd HH:mm');

    for (const e of events) {
      if (Number.isNaN(e.time.getTime())) continue;
      const key = getKey(e.time);
      let b = buckets.get(key);
      if (!b) {
        b = { minute: key, auth: 0, dns: 0, firewall: 0, malware: 0 };
        buckets.set(key, b);
      }
      if (e.source === 'auth') b.auth += 1;
      else if (e.source === 'dns') b.dns += 1;
      else if (e.source === 'firewall' && (e.action ?? '').toLowerCase() === 'deny') b.firewall += 1;
      else if (e.source === 'malware') b.malware += 1;
    }

    return Array.from(buckets.values()).sort(
      (a, b) => a.minute.localeCompare(b.minute)
    );
  }, [events]);

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
      <h3>Events per minute (by source)</h3>
      <p className="timeline-chart__desc">Selected incident only. Changes when you pick another.</p>
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={data} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
          <XAxis dataKey="minute" tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          <YAxis tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            labelFormatter={(_, payload) => (payload?.[0]?.payload as Bucket)?.minute ?? ''}
          />
          <Legend />
          <Bar dataKey="auth" stackId="a" fill="#3b82f6" name="Auth" radius={[0, 0, 0, 0]} />
          <Bar dataKey="dns" stackId="a" fill="#22d3ee" name="DNS events" radius={[0, 0, 0, 0]} />
          <Bar dataKey="firewall" stackId="a" fill="#f59e0b" name="Firewall denials" radius={[0, 0, 0, 0]} />
          <Bar dataKey="malware" stackId="a" fill="#8b5cf6" name="Malware" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

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
import type { NormalizedEvent } from '../lib/types';
import type { FirewallLogRow } from '../lib/types';

const SSH_PORT = '22';
const MIN_SSH_ATTEMPTS_ALARM = 10;

function isPrivateIp(ip: string): boolean {
  if (!ip?.trim()) return false;
  const s = ip.trim();
  if (s.startsWith('10.')) return true;
  if (s.startsWith('192.168.')) return true;
  if (s.startsWith('172.')) {
    const second = parseInt(s.slice(4).split('.')[0] ?? '', 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

const COLORS = {
  auth: '#3b82f6',
  dns: '#22d3ee',
  firewall: '#f59e0b',
  malware: '#8b5cf6',
} as const;

const SOURCES: Array<{ key: 'auth' | 'dns' | 'firewall' | 'malware'; name: string }> = [
  { key: 'auth', name: 'Auth' },
  { key: 'dns', name: 'DNS' },
  { key: 'firewall', name: 'Firewall' },
  { key: 'malware', name: 'Malware' },
];

type Props = {
  events: NormalizedEvent[];
};

type IpCounts = {
  ip: string;
  auth: number;
  dns: number;
  firewall: number;
  malware: number;
  total: number;
  alarming: boolean;
  alarmReason?: string;
};

export function IpCorrelationChart({ events }: Props) {
  const { data, alarmingIPs } = useMemo(() => {
    const byIp = new Map<string, { auth: number; dns: number; firewall: number; malware: number }>();
    const firewallSshByIp = new Map<string, number>();

    for (const e of events) {
      const ip = e.entity_ip?.trim();
      if (!ip) continue;
      let row = byIp.get(ip);
      if (!row) {
        row = { auth: 0, dns: 0, firewall: 0, malware: 0 };
        byIp.set(ip, row);
      }
      if (e.source === 'auth') row.auth += 1;
      else if (e.source === 'dns') row.dns += 1;
      else if (e.source === 'firewall') {
        row.firewall += 1;
        const port = (e.raw as FirewallLogRow).destination_port;
        if (port === SSH_PORT && !isPrivateIp(ip)) {
          firewallSshByIp.set(ip, (firewallSshByIp.get(ip) ?? 0) + 1);
        }
      } else if (e.source === 'malware') row.malware += 1;
    }

    const alarmingSet = new Set<string>();
    const alarmReasonByIp = new Map<string, string>();
    for (const [ip, count] of firewallSshByIp.entries()) {
      if (count >= MIN_SSH_ATTEMPTS_ALARM) {
        alarmingSet.add(ip);
        alarmReasonByIp.set(ip, `${count} SSH (port 22) attempts from external IP`);
      }
    }

    const list: IpCounts[] = Array.from(byIp.entries()).map(([ip, row]) => ({
      ip,
      ...row,
      total: row.auth + row.dns + row.firewall + row.malware,
      alarming: alarmingSet.has(ip),
      alarmReason: alarmReasonByIp.get(ip),
    }));

    return { data: list.sort((a, b) => b.total - a.total), alarmingIPs: alarmingSet };
  }, [events]);

  if (data.length === 0) {
    return (
      <div className="ip-correlation">
        <h3>Correlation: IP address</h3>
        <p className="ip-correlation__empty">No IPs to show (events need source/client IP).</p>
      </div>
    );
  }

  return (
    <div className="ip-correlation">
      <h3>Correlation: IP address</h3>
      <p className="ip-correlation__legend-desc">
        All IPs by total events ({data.length} total). Stack = events per log type.{' '}
        {alarmingIPs.size > 0 && (
          <span className="ip-correlation__alarm-legend">Red IP ⚠ = alarming (external IP, many SSH / port 22 attempts).</span>
        )}
      </p>
      <div className="ip-correlation__legend">
        {SOURCES.map(({ key, name }) => (
          <span key={key} className="ip-correlation__legend-item" style={{ color: COLORS[key] }}>
            ● {name}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={Math.max(280, data.length * 28)}>
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 8, right: 8, left: 8, bottom: 8 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
          <XAxis type="number" tick={{ fontSize: 11 }} stroke="var(--text-muted)" />
          <YAxis
            type="category"
            dataKey="ip"
            width={220}
            tick={({ x, y, payload }) => {
              const ip = (typeof payload?.value !== 'undefined' ? payload.value : payload) as string;
              const row = ip ? data.find((r) => r.ip === ip) : null;
              const alarming = row?.alarming;
              const reason = row?.alarmReason;
              const shortReason = reason ? reason.replace(/ from external IP$/, '').replace(/^(\d+) SSH \(port 22\) attempts/, '⚠ $1× port 22') : '⚠';
              return (
                <g transform={`translate(${x},${y})`}>
                  <text x={0} y={0} dy={4} textAnchor="end" fill={alarming ? '#dc2626' : 'var(--text-muted)'} fontSize={11}>
                    {ip}
                  </text>
                  {alarming && (
                    <text x={4} y={0} dy={4} textAnchor="start" fill="#dc2626" fontSize={10}>
                      {shortReason}
                    </text>
                  )}
                </g>
              );
            }}
          />
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)' }}
            labelStyle={{ color: 'var(--text)' }}
            formatter={(value: number, name: string) => [`${value} events`, name]}
            labelFormatter={(label) => `IP: ${label}`}
            content={({ active, payload: tooltipPayload, label }) => {
              if (!active || !tooltipPayload?.length || !label) return null;
              const row = data.find((r) => r.ip === label);
              return (
                <div className="ip-correlation-tooltip" style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px' }}>
                  <div style={{ fontWeight: 600, marginBottom: 4, color: row?.alarming ? '#dc2626' : 'var(--text)' }}>
                    IP: {label}
                    {row?.alarming && ' ⚠'}
                  </div>
                  {row?.alarmReason && (
                    <div style={{ fontSize: 11, color: '#dc2626', marginBottom: 4 }}>{row.alarmReason}</div>
                  )}
                  {tooltipPayload.map((entry) => (
                    <div key={entry.dataKey} style={{ fontSize: 12 }}>
                      {entry.name}: {entry.value} events
                    </div>
                  ))}
                </div>
              );
            }}
          />
          <Legend formatter={(value) => <span style={{ color: 'var(--text)' }}>{value}</span>} />
          <Bar dataKey="auth" stackId="a" fill={COLORS.auth} name="Auth" radius={[0, 0, 0, 0]} />
          <Bar dataKey="dns" stackId="a" fill={COLORS.dns} name="DNS" radius={[0, 0, 0, 0]} />
          <Bar dataKey="firewall" stackId="a" fill={COLORS.firewall} name="Firewall" radius={[0, 0, 0, 0]} />
          <Bar dataKey="malware" stackId="a" fill={COLORS.malware} name="Malware" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

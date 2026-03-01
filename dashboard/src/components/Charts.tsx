import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import type { AuthLogRow } from '../lib/csv';
import type { DnsLogRow } from '../lib/csv';
import type { FirewallLogRow } from '../lib/csv';
const CHART_COLORS = ['#3b82f6', '#22d3ee', '#f59e0b', '#8b5cf6', '#ef4444'];

export function AuthByUserChart({ data }: { data: AuthLogRow[] }) {
  const byUser = data.reduce<Record<string, number>>((acc, row) => {
    acc[row.user] = (acc[row.user] ?? 0) + 1;
    return acc;
  }, {});
  const chartData = Object.entries(byUser)
    .map(([user, count]) => ({ name: user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  return (
    <div className="chart-panel">
      <h3>Auth events by user</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip />
          <Bar dataKey="count" fill={CHART_COLORS[0]} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function TopDomainsChart({ data }: { data: DnsLogRow[] }) {
  const byDomain = data.reduce<Record<string, number>>((acc, row) => {
    acc[row.domain_queried] = (acc[row.domain_queried] ?? 0) + 1;
    return acc;
  }, {});
  const chartData = Object.entries(byDomain)
    .map(([domain, count]) => ({ name: domain, value: count }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);
  return (
    <div className="chart-panel">
      <h3>Top domains queried</h3>
      <ResponsiveContainer width="100%" height={220}>
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={80}
            label={({ name, value }) => `${name}: ${value}`}
          >
            {chartData.map((_, i) => (
              <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function FirewallActionsChart({ data }: { data: FirewallLogRow[] }) {
  const byAction = data.reduce<Record<string, number>>((acc, row) => {
    acc[row.action] = (acc[row.action] ?? 0) + 1;
    return acc;
  }, {});
  const chartData = Object.entries(byAction).map(([action, count]) => ({
    name: action,
    count,
  }));
  return (
    <div className="chart-panel">
      <h3>Firewall actions</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} margin={{ top: 8, right: 8, left: 8, bottom: 8 }}>
          <XAxis dataKey="name" tick={{ fontSize: 12 }} />
          <YAxis tick={{ fontSize: 12 }} />
          <Tooltip />
          <Bar dataKey="count" fill={CHART_COLORS[1]} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

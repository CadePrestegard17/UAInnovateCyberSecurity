import { useMemo } from 'react';
import type { AuthLogRow, DnsLogRow, FirewallLogRow } from '../lib/types';
import type { Incident } from '../lib/correlation';

type Props = {
  incident: Incident | null;
  auth: AuthLogRow[];
  dns: DnsLogRow[];
  firewall: FirewallLogRow[];
};

function isDenied(action: string): boolean {
  return (action ?? '').toLowerCase() !== 'success';
}

export function TopTables({ incident, auth, dns, firewall }: Props) {
  const primaryEntity = incident?.primary_entity ?? '';

  const authTopIps = useMemo(() => {
    const byIp = new Map<string, number>();
    for (const row of auth) {
      if (!isDenied(row.action)) continue;
      const ip = (row.source_ip ?? '').trim();
      if (ip) byIp.set(ip, (byIp.get(ip) ?? 0) + 1);
    }
    return Array.from(byIp.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [auth]);

  const authTopUsers = useMemo(() => {
    const byUser = new Map<string, number>();
    for (const row of auth) {
      if (!isDenied(row.action)) continue;
      const user = (row.user ?? '').trim();
      if (user) byUser.set(user, (byUser.get(user) ?? 0) + 1);
    }
    return Array.from(byUser.entries())
      .map(([user, count]) => ({ user, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [auth]);

  const dnsTopDomains = useMemo(() => {
    const filtered = primaryEntity
      ? dns.filter((r) => (r.client_ip ?? '').trim() === primaryEntity)
      : dns;
    const byDomain = new Map<string, number>();
    for (const row of filtered) {
      const domain = (row.domain_queried ?? '').trim();
      if (domain) byDomain.set(domain, (byDomain.get(domain) ?? 0) + 1);
    }
    return Array.from(byDomain.entries())
      .map(([domain, count]) => ({ domain, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }, [dns, primaryEntity]);

  const dnsBeaconFreq = useMemo(() => {
    if (!primaryEntity) return null;
    const filtered = dns.filter((r) => (r.client_ip ?? '').trim() === primaryEntity);
    const total = filtered.length;
    if (total === 0) return null;
    const minTs = Math.min(...filtered.map((r) => new Date(r.timestamp).getTime()).filter((t) => !Number.isNaN(t)));
    const maxTs = Math.max(...filtered.map((r) => new Date(r.timestamp).getTime()).filter((t) => !Number.isNaN(t)));
    const spanMinutes = (maxTs - minTs) / (60 * 1000) || 1;
    return { total, queriesPerMinute: (total / spanMinutes).toFixed(1), spanMinutes };
  }, [dns, primaryEntity]);

  const firewallTopDests = useMemo(() => {
    const filtered = primaryEntity
      ? firewall.filter((r) => (r.source_ip ?? '').trim() === primaryEntity)
      : firewall;
    const byDest = new Map<string, { allow: number; deny: number }>();
    for (const row of filtered) {
      const key = `${(row.destination_ip ?? '').trim()}:${(row.destination_port ?? '').trim()}`;
      if (!key || key === ':') continue;
      let rec = byDest.get(key);
      if (!rec) rec = { allow: 0, deny: 0 };
      if ((row.action ?? '').toLowerCase() === 'allow') rec.allow += 1;
      else rec.deny += 1;
      byDest.set(key, rec);
    }
    return Array.from(byDest.entries())
      .map(([dest, rec]) => ({ dest, ...rec, total: rec.allow + rec.deny }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 10);
  }, [firewall, primaryEntity]);

  const firewallTotals = useMemo(() => {
    const filtered = primaryEntity
      ? firewall.filter((r) => (r.source_ip ?? '').trim() === primaryEntity)
      : firewall;
    let allow = 0;
    let deny = 0;
    for (const row of filtered) {
      if ((row.action ?? '').toLowerCase() === 'allow') allow += 1;
      else deny += 1;
    }
    return { allow, deny };
  }, [firewall, primaryEntity]);

  return (
    <div className="top-tables">
      <div className="top-tables__panel">
        <h3>Auth — top attacker IPs (denied)</h3>
        <div className="top-tables__table-wrap">
          <table className="top-tables__table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Denied</th>
              </tr>
            </thead>
            <tbody>
              {authTopIps.map(({ ip, count }) => (
                <tr key={ip}>
                  <td className="top-tables__mono">{ip}</td>
                  <td>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <h3>Auth — top targeted users</h3>
        <div className="top-tables__table-wrap">
          <table className="top-tables__table">
            <thead>
              <tr>
                <th>User</th>
                <th>Denied</th>
              </tr>
            </thead>
            <tbody>
              {authTopUsers.map(({ user, count }) => (
                <tr key={user}>
                  <td>{user}</td>
                  <td>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="top-tables__panel">
        <h3>DNS — top domains{primaryEntity ? ` (${primaryEntity})` : ''}</h3>
        {dnsBeaconFreq && (
          <p className="top-tables__beacon">
            Beacon frequency: {dnsBeaconFreq.total} queries over {dnsBeaconFreq.spanMinutes.toFixed(0)} min
            ≈ {dnsBeaconFreq.queriesPerMinute}/min
          </p>
        )}
        <div className="top-tables__table-wrap">
          <table className="top-tables__table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {dnsTopDomains.map(({ domain, count }) => (
                <tr key={domain}>
                  <td>{domain}</td>
                  <td>{count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="top-tables__panel">
        <h3>Firewall — top destination_ip:port{primaryEntity ? ` (from ${primaryEntity})` : ''}</h3>
        <p className="top-tables__beacon">
          Allowed: {firewallTotals.allow} — Denied: {firewallTotals.deny}
        </p>
        <div className="top-tables__table-wrap">
          <table className="top-tables__table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Allow</th>
                <th>Deny</th>
              </tr>
            </thead>
            <tbody>
              {firewallTopDests.map(({ dest, allow, deny }) => (
                <tr key={dest}>
                  <td className="top-tables__mono">{dest}</td>
                  <td>{allow}</td>
                  <td>{deny}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

import { useMemo, useState } from 'react';
import { format, isValid } from 'date-fns';
import type { NormalizedEvent } from '../lib/types';

type Props = {
  events: NormalizedEvent[];
};

const SOURCES: Array<NormalizedEvent['source']> = ['auth', 'dns', 'firewall', 'malware'];

export function EventsTable({ events }: Props) {
  const [sourceFilter, setSourceFilter] = useState<NormalizedEvent['source'] | ''>('');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    let list = events;
    if (sourceFilter) {
      list = list.filter((e) => e.source === sourceFilter);
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((e) => {
        const parts = [
          e.entity_ip,
          e.user,
          e.hostname,
          e.domain,
          e.destination_ip,
          e.action,
          e.destination_port?.toString(),
        ].filter(Boolean);
        return parts.some((p) => String(p).toLowerCase().includes(q));
      });
    }
    return [...list].sort((a, b) => a.time.getTime() - b.time.getTime());
  }, [events, sourceFilter, search]);

  return (
    <div className="events-table">
      <h3>Unified events</h3>
      <div className="events-table__toolbar">
        <label className="events-table__filter">
          <span>Source</span>
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as NormalizedEvent['source'] | '')}
          >
            <option value="">All</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <label className="events-table__filter">
          <span>Search</span>
          <input
            type="search"
            placeholder="IP, user, domain…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </label>
      </div>
      <div className="events-table__wrap">
        <table className="events-table__table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Entity IP</th>
              <th>User</th>
              <th>Domain</th>
              <th>Destination</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e, i) => (
              <tr key={i}>
                <td className="events-table__mono">{isValid(e.time) ? format(e.time, 'yyyy-MM-dd HH:mm:ss') : '—'}</td>
                <td><span className={`events-table__source events-table__source--${e.source}`}>{e.source}</span></td>
                <td className="events-table__mono">{e.entity_ip ?? '—'}</td>
                <td>{e.user ?? '—'}</td>
                <td>{e.domain ?? '—'}</td>
                <td className="events-table__mono">
                  {e.destination_ip != null ? `${e.destination_ip}${e.destination_port != null ? ':' + e.destination_port : ''}` : '—'}
                </td>
                <td>{e.action ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="events-table__count">Showing {filtered.length} of {events.length} events</p>
    </div>
  );
}

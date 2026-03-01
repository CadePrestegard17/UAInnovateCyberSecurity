import { useEffect, useState, useCallback, useRef } from 'react';
import {
  loadAuthLogs,
  loadDnsLogs,
  loadFirewallLogs,
  loadMalwareAlerts,
  loadFromFiles,
  normalizeAllLogs,
} from './lib/csv';
import type { CsvFileSet } from './lib/csv';
import { buildIncidents } from './lib/correlation';
import type { AuthLogRow, DnsLogRow, FirewallLogRow, MalwareAlertRow, NormalizedEvent } from './lib/types';
import type { Incident } from './lib/correlation';
import { toBackendEvents, fetchAddData, fetchPredict, type RiskResponse } from './lib/riskApi';
import { IncidentList } from './components/IncidentList';
import { LoadCsvSection, type DataSource } from './components/LoadCsvSection';
import { RiskForecast } from './components/RiskForecast';
import { SummaryCards } from './components/SummaryCards';
import { TimelineChart } from './components/TimelineChart';
import { TimeCorrelationChart } from './components/TimeCorrelationChart';
import { IpOverTimeChart } from './components/IpOverTimeChart';
import { TopTables } from './components/TopTables';
import { EventsTable } from './components/EventsTable';
import { HowToUse } from './components/HowToUse';
import './App.css';

function applyData(
  a: AuthLogRow[],
  d: DnsLogRow[],
  f: FirewallLogRow[],
  m: MalwareAlertRow[],
  setAuth: (v: AuthLogRow[]) => void,
  setDns: (v: DnsLogRow[]) => void,
  setFirewall: (v: FirewallLogRow[]) => void,
  setMalware: (v: MalwareAlertRow[]) => void,
  setAllEvents: (v: NormalizedEvent[]) => void,
  setIncidents: (v: Incident[]) => void,
  setSelectedIncident: (v: Incident | null) => void,
  setRisk: (v: RiskResponse | null) => void,
  setRiskLoading: (v: boolean) => void,
  setRiskError: (v: string | null) => void
) {
  setAuth(a);
  setDns(d);
  setFirewall(f);
  setMalware(m);
  const allEvents = normalizeAllLogs(a, d, f, m);
  setAllEvents(allEvents);
  const incs = buildIncidents(allEvents, a, d, f, m);
  setIncidents(incs);
  setSelectedIncident(incs[0] ?? null);
  // Call risk API (async, non-blocking)
  if (allEvents.length > 0) {
    setRiskLoading(true);
    setRiskError(null);
    const backendEvents = toBackendEvents(allEvents);
    fetchAddData(backendEvents)
      .then(() => fetchPredict(backendEvents))
      .then((res) => {
        setRisk(res);
        setRiskLoading(false);
      })
      .catch((err) => {
        setRiskError(err instanceof Error ? err.message : 'Request failed');
        setRisk(null);
        setRiskLoading(false);
      });
  } else {
    setRisk(null);
    setRiskError(null);
  }
}

export default function App() {
  const [auth, setAuth] = useState<AuthLogRow[]>([]);
  const [dns, setDns] = useState<DnsLogRow[]>([]);
  const [firewall, setFirewall] = useState<FirewallLogRow[]>([]);
  const [malware, setMalware] = useState<MalwareAlertRow[]>([]);
  const [allEvents, setAllEvents] = useState<NormalizedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dataSource, setDataSource] = useState<DataSource>('bundled');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [risk, setRisk] = useState<RiskResponse | null>(null);
  const [riskLoading, setRiskLoading] = useState(false);
  const [riskError, setRiskError] = useState<string | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [replayTimeMs, setReplayTimeMs] = useState<number | null>(null);
  const replayIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const uploadedFilesRef = useRef<CsvFileSet | null>(null);

  const WINDOW_MS = 15 * 60 * 1000;
  const REPLAY_DURATION_MS = 60 * 1000; // 60s wall clock for full replay
  const REPLAY_TICK_MS = 2000; // re-predict every 2s

  const startReplay = useCallback(() => {
    if (allEvents.length === 0) return;
    const times = allEvents.map((e) => e.time.getTime());
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    const span = maxT - minT || 1;
    setReplaying(true);
    setRiskError(null);
    let current = minT;
    setReplayTimeMs(current);
    const advance = span / (REPLAY_DURATION_MS / REPLAY_TICK_MS);
    replayIntervalRef.current = setInterval(() => {
      current = Math.min(current + advance, maxT);
      setReplayTimeMs(current);
      const windowStart = current - WINDOW_MS;
      const inWindow = allEvents.filter((e) => {
        const t = e.time.getTime();
        return t >= windowStart && t <= current;
      });
      const backendEvents = toBackendEvents(inWindow);
      if (backendEvents.length > 0) {
        fetchPredict(backendEvents)
          .then(setRisk)
          .catch((err) => setRiskError(err instanceof Error ? err.message : 'Predict failed'));
      }
      if (current >= maxT) {
        if (replayIntervalRef.current) clearInterval(replayIntervalRef.current);
        replayIntervalRef.current = null;
        setReplaying(false);
        setReplayTimeMs(null);
      }
    }, REPLAY_TICK_MS);
  }, [allEvents]);

  const stopReplay = useCallback(() => {
    if (replayIntervalRef.current) {
      clearInterval(replayIntervalRef.current);
      replayIntervalRef.current = null;
    }
    setReplaying(false);
    setReplayTimeMs(null);
  }, []);

  // Debounced risk refresh for event-intensity brush/zoom: run predictor when user moves the slider
  const refreshRiskDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingBrushEventsRef = useRef<NormalizedEvent[] | null>(null);
  const allEventsRef = useRef(allEvents);
  allEventsRef.current = allEvents;
  const refreshRisk = useCallback((eventsSubset?: NormalizedEvent[]) => {
    pendingBrushEventsRef.current = eventsSubset ?? null;
    if (refreshRiskDebounceRef.current) clearTimeout(refreshRiskDebounceRef.current);
    refreshRiskDebounceRef.current = setTimeout(() => {
      const eventsToUse = pendingBrushEventsRef.current ?? allEventsRef.current;
      if (eventsToUse.length === 0) return;
      setRiskLoading(true);
      setRiskError(null);
      fetchPredict(toBackendEvents(eventsToUse))
        .then(setRisk)
        .catch((err) => {
          setRiskError(err instanceof Error ? err.message : 'Request failed');
          setRisk(null);
        })
        .finally(() => setRiskLoading(false));
    }, 300);
  }, []);

  useEffect(() => {
    return () => {
      if (replayIntervalRef.current) clearInterval(replayIntervalRef.current);
      if (refreshRiskDebounceRef.current) clearTimeout(refreshRiskDebounceRef.current);
    };
  }, []);

  const loadBundled = useCallback(async () => {
    setLoading(true);
    setError(null);
    setUploadError(null);
    try {
      const [a, d, f, m] = await Promise.all([
        loadAuthLogs(),
        loadDnsLogs(),
        loadFirewallLogs(),
        loadMalwareAlerts(),
      ]);
      applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident, setRisk, setRiskLoading, setRiskError);
      setDataSource('bundled');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUploaded = useCallback(async (files: CsvFileSet) => {
    setLoading(true);
    setError(null);
    setUploadError(null);
    uploadedFilesRef.current = files;
    try {
      const [a, d, f, m] = await loadFromFiles(files);
      applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident, setRisk, setRiskLoading, setRiskError);
      setDataSource('uploaded');
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Failed to parse uploaded files');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadData = useCallback(() => {
    if (dataSource === 'bundled') {
      loadBundled();
    } else if (uploadedFilesRef.current) {
      loadFromFiles(uploadedFilesRef.current)
        .then(([a, d, f, m]) => {
          applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident, setRisk, setRiskLoading, setRiskError);
        })
        .catch((err) => setUploadError(err instanceof Error ? err.message : 'Reload failed'));
    }
  }, [dataSource, loadBundled]);

  useEffect(() => {
    loadBundled();
  }, [loadBundled]);

  if (loading && incidents.length === 0 && dataSource === 'bundled') {
    return (
      <div className="app">
        <header className="header">
          <h1 className="header__title">A Little Bit of Hope — SOC Dashboard</h1>
          <span className="header__version header__version--muted">v{__APP_VERSION__}</span>
          <span className="header__status header__status--muted">Bundled sample data</span>
          <button type="button" className="header__reload" onClick={loadData} disabled>
            Reload Data
          </button>
        </header>
        <main className="main main--loading">
          <p className="loading">Loading CSV data…</p>
        </main>
      </div>
    );
  }

  if (error && incidents.length === 0) {
    return (
      <div className="app">
        <header className="header">
          <h1 className="header__title">A Little Bit of Hope — SOC Dashboard</h1>
          <span className="header__version header__version--muted">v{__APP_VERSION__}</span>
          <span className="header__status header__status--muted">Bundled sample data</span>
          <button type="button" className="header__reload" onClick={loadBundled}>
            Reload Data
          </button>
        </header>
        <main className="main">
          <p className="error">Error: {error}</p>
          <p>Ensure the app is served so that /data/*.csv files are available.</p>
        </main>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <h1 className="header__title">A Little Bit of Hope — SOC Dashboard</h1>
        <span className="header__version" title="Dashboard version">v{__APP_VERSION__}</span>
        <span className="header__status" title="Current data source">
          {dataSource === 'bundled' ? 'Bundled sample data' : 'Uploaded files'}
        </span>
        <button type="button" className="header__reload" onClick={loadData} disabled={loading}>
          {loading ? 'Loading…' : 'Reload Data'}
        </button>
      </header>

      <section className="risk-section risk-section--header">
        <div className="risk-section__actions">
          <button
            type="button"
            className="risk-section__btn"
            onClick={startReplay}
            disabled={allEvents.length === 0 || replaying || riskLoading}
          >
            Replay
          </button>
          {replaying && (
            <button type="button" className="risk-section__btn risk-section__btn--stop" onClick={stopReplay}>
              Stop
            </button>
          )}
          {replaying && replayTimeMs !== null && (
            <span className="risk-section__replay-time">
              Replaying — {new Date(replayTimeMs).toLocaleTimeString()}
            </span>
          )}
        </div>
      </section>

      <div className="layout">
        <aside className="sidebar">
          <LoadCsvSection
            dataSource={dataSource}
            onUseBundled={loadBundled}
            onUploadComplete={loadUploaded}
            uploadError={uploadError}
            clearUploadError={() => setUploadError(null)}
          />
          <IncidentList
            incidents={incidents}
            selectedId={selectedIncident?.id ?? null}
            onSelect={setSelectedIncident}
          />
          <HowToUse />
        </aside>

        <main className="main main--with-sidebar">
          {selectedIncident ? (
            <>
              <section className="panel-section incident-focus">
                <p className="incident-focus__text">
                  <strong>For this incident we're focused on this IP: {selectedIncident.primary_entity}</strong>
                  {selectedIncident.id === 'CASE_A' ? (
                    <> — That's the <strong>attacker</strong> (mass login / brute-force). The tables below show this attacker's auth attempts, DNS lookups, and firewall connections.</>
                  ) : (
                    <> — That's the <strong>suspected infected host</strong> (beaconing). The tables below show this host's DNS queries and firewall traffic.</>
                  )}
                </p>
              </section>
              <section className="panel-section">
                <SummaryCards incident={selectedIncident} malware={malware} />
              </section>
              <section className="panel-section">
                <TimelineChart
                  events={selectedIncident.related_events}
                  onBrushChange={refreshRisk}
                />
              </section>
              <section className="panel-section risk-section risk-section--inline">
                <p className="risk-section__hint">Updates as you move the time slider above. Very narrow windows (fewer events) keep the last score so the rate doesn’t jump to 100%.</p>
                <RiskForecast risk={risk} loading={riskLoading} error={riskError} />
              </section>
              <section className="panel-section">
                <TopTables incident={selectedIncident} auth={auth} dns={dns} firewall={firewall} />
              </section>
              <section className="panel-section">
                <TimeCorrelationChart events={allEvents} />
              </section>
              <section className="panel-section">
                <IpOverTimeChart events={allEvents} />
              </section>
              <section className="panel-section">
                <EventsTable events={selectedIncident.related_events} />
              </section>
            </>
          ) : (
            <p className="main__empty">Select an incident from the list.</p>
          )}
        </main>
      </div>
    </div>
  );
}

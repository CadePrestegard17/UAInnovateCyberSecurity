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
import { IncidentList } from './components/IncidentList';
import { LoadCsvSection, type DataSource } from './components/LoadCsvSection';
import { SummaryCards } from './components/SummaryCards';
import { TimelineChart } from './components/TimelineChart';
import { TimeCorrelationChart } from './components/TimeCorrelationChart';
import { IpOverTimeChart } from './components/IpOverTimeChart';
import { TopTables } from './components/TopTables';
import { EventsTable } from './components/EventsTable';
import { HowToUse } from './components/HowToUse';
import { AlertSignupSection } from './components/AlertSignupSection';
import './App.css';

const ALERT_PROMPT_DISMISSED_KEY = 'soc-alert-prompt-dismissed';

const HIGH_RISK_SEVERITY = 70;

const ALERT_PHONE_KEY = 'soc-alert-phone';
const ALERT_EMAIL_KEY = 'soc-alert-email';

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
  setSelectedIncident: (v: Incident | null) => void
): Incident[] {
  setAuth(a);
  setDns(d);
  setFirewall(f);
  setMalware(m);
  const allEvents = normalizeAllLogs(a, d, f, m);
  setAllEvents(allEvents);
  const incs = buildIncidents(allEvents, a, d, f, m);
  setIncidents(incs);
  setSelectedIncident(incs[0] ?? null);
  return incs;
}

function buildAlertMessage(incident: Incident): string {
  const firstHighlight = incident.highlights[0] ?? incident.title;
  return `SOC Alert: ${incident.title} (Severity ${incident.severity}). ${firstHighlight} Entity: ${incident.primary_entity}. Check dashboard.`;
}

const alertApiUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_ALERT_API_URL) || 'http://localhost:3001';

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
  const [highRiskIncident, setHighRiskIncident] = useState<Incident | null>(null);
  const [alertPhone, setAlertPhone] = useState<string>(() => {
    try {
      return localStorage.getItem(ALERT_PHONE_KEY) || '';
    } catch {
      return '';
    }
  });
  const [alertEmail, setAlertEmail] = useState<string>(() => {
    try {
      return localStorage.getItem(ALERT_EMAIL_KEY) || '';
    } catch {
      return '';
    }
  });
  const [alertToast, setAlertToast] = useState<{ type: 'sent' | 'failed' | 'no_phone'; message: string } | null>(null);
  const [alertPromptDismissed, setAlertPromptDismissed] = useState(() => {
    try {
      return sessionStorage.getItem(ALERT_PROMPT_DISMISSED_KEY) === '1';
    } catch {
      return false;
    }
  });
  const uploadedFilesRef = useRef<CsvFileSet | null>(null);

  const dismissAlertPrompt = useCallback(() => {
    setAlertPromptDismissed(true);
    try {
      sessionStorage.setItem(ALERT_PROMPT_DISMISSED_KEY, '1');
    } catch {
      /* ignore */
    }
  }, []);

  const persistAlertPhone = useCallback((phone: string) => {
    setAlertPhone(phone);
    try {
      localStorage.setItem(ALERT_PHONE_KEY, phone);
    } catch {
      /* ignore */
    }
  }, []);

  const persistAlertEmail = useCallback((email: string) => {
    setAlertEmail(email);
    try {
      localStorage.setItem(ALERT_EMAIL_KEY, email);
    } catch {
      /* ignore */
    }
  }, []);

  const loadBundled = useCallback(async () => {
    setLoading(true);
    setError(null);
    setUploadError(null);
    setHighRiskIncident(null);
    try {
      const [a, d, f, m] = await Promise.all([
        loadAuthLogs(),
        loadDnsLogs(),
        loadFirewallLogs(),
        loadMalwareAlerts(),
      ]);
      const incs = applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident);
      setDataSource('bundled');
      const highRisk = incs.find((i) => i.severity >= HIGH_RISK_SEVERITY) ?? incs.reduce<Incident | null>((best, i) => (i.severity > (best?.severity ?? 0) ? i : best), null);
      if (highRisk && highRisk.severity >= HIGH_RISK_SEVERITY) setHighRiskIncident(highRisk);
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
    setHighRiskIncident(null);
    uploadedFilesRef.current = files;
    try {
      const [a, d, f, m] = await loadFromFiles(files);
      const incs = applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident);
      setDataSource('uploaded');
      const highRisk = incs.find((i) => i.severity >= HIGH_RISK_SEVERITY) ?? incs.reduce<Incident | null>((best, i) => (i.severity > (best?.severity ?? 0) ? i : best), null);
      if (highRisk && highRisk.severity >= HIGH_RISK_SEVERITY) setHighRiskIncident(highRisk);
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
      setHighRiskIncident(null);
      loadFromFiles(uploadedFilesRef.current)
        .then(([a, d, f, m]) => {
          const incs = applyData(a, d, f, m, setAuth, setDns, setFirewall, setMalware, setAllEvents, setIncidents, setSelectedIncident);
          const highRisk = incs.find((i) => i.severity >= HIGH_RISK_SEVERITY) ?? incs.reduce<Incident | null>((best, i) => (i.severity > (best?.severity ?? 0) ? i : best), null);
          if (highRisk && highRisk.severity >= HIGH_RISK_SEVERITY) setHighRiskIncident(highRisk);
        })
        .catch((err) => setUploadError(err instanceof Error ? err.message : 'Reload failed'));
    }
  }, [dataSource, loadBundled]);

  useEffect(() => {
    if (!highRiskIncident) return;
    const phone = alertPhone.trim();
    const email = alertEmail.trim();
    if (!phone && !email) {
      setAlertToast({ type: 'no_phone', message: 'High-risk incident detected. Add a phone or email in the sidebar to get alerts next time.' });
      setHighRiskIncident(null);
      return;
    }
    const message = buildAlertMessage(highRiskIncident);
    let cancelled = false;
    (async () => {
      const parts: string[] = [];
      let hasFailure = false;
      if (email) {
        try {
          const res = await fetch(`${alertApiUrl}/api/alert-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: email, message }),
          });
          const data = await res.json().catch(() => ({}));
          if (cancelled) return;
          if (res.ok) parts.push(`Email sent to ${email}`);
          else {
            parts.push(`Email failed: ${data.error || res.status}`);
            hasFailure = true;
          }
        } catch (err) {
          if (!cancelled) {
            parts.push(`Email failed: ${err instanceof Error ? err.message : 'Failed to send'}`);
            hasFailure = true;
          }
        }
      }
      if (phone) {
        try {
          const res = await fetch(`${alertApiUrl}/api/alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: phone, message }),
          });
          const data = await res.json().catch(() => ({}));
          if (cancelled) return;
          if (res.ok) parts.push(`SMS sent to ${phone}`);
          else {
            parts.push(`SMS failed: ${data.error || res.status}`);
            hasFailure = true;
          }
        } catch (err) {
          if (!cancelled) {
            parts.push(`SMS failed: ${err instanceof Error ? err.message : 'Failed to send'}`);
            hasFailure = true;
          }
        }
      }
      if (!cancelled) {
        setAlertToast({
          type: hasFailure ? 'failed' : 'sent',
          message: parts.length ? parts.join('. ') : 'No alert sent.',
        });
        setHighRiskIncident(null);
      }
    })();
    return () => { cancelled = true; };
  }, [highRiskIncident, alertPhone, alertEmail]);

  useEffect(() => {
    if (!alertToast) return;
    const t = window.setTimeout(() => setAlertToast(null), 6000);
    return () => clearTimeout(t);
  }, [alertToast]);

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
          <AlertSignupSection
            phone={alertPhone}
            onPhoneChange={persistAlertPhone}
            email={alertEmail}
            onEmailChange={persistAlertEmail}
          />
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
                  events={allEvents.filter(
                    (e) =>
                      e.time >= selectedIncident.start &&
                      e.time <= selectedIncident.end
                  )}
                />
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

      {!alertPhone.trim() && !alertPromptDismissed && (
        <div className="alert-prompt-overlay" role="dialog" aria-labelledby="alert-prompt-title" aria-modal="true">
          <div className="alert-prompt">
            <button
              type="button"
              className="alert-prompt__close"
              onClick={dismissAlertPrompt}
              aria-label="Close"
            >
              ×
            </button>
            <h2 id="alert-prompt-title" className="alert-prompt__title">Want to get text alerts for suspicious activity?</h2>
            <p className="alert-prompt__desc">When we detect a high-risk incident, we can send you an SMS. Enter your phone number in the sidebar to the left (include country code, e.g. +15551234567).</p>
            <button type="button" className="alert-prompt__dismiss" onClick={dismissAlertPrompt}>
              Maybe later
            </button>
          </div>
        </div>
      )}

      {alertToast && (
        <div
          className={`alert-toast alert-toast--${alertToast.type}`}
          role="status"
          aria-live="polite"
        >
          <span className="alert-toast__message">{alertToast.message}</span>
          <button
            type="button"
            className="alert-toast__dismiss"
            onClick={() => setAlertToast(null)}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}

import Papa from 'papaparse';
import type { AuthLogRow, DnsLogRow, FirewallLogRow, MalwareAlertRow, NormalizedEvent } from './types';
import { parseTimestamp } from './time';

const DATA_BASE = '/data';

async function fetchAndParse<T>(filename: string): Promise<T[]> {
  const url = `${DATA_BASE}/${filename}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to load ${filename}: ${res.statusText}`);
  const text = await res.text();
  const parsed = Papa.parse<T>(text, { header: true, skipEmptyLines: true });
  return parsed.data;
}

export async function loadAuthLogs(): Promise<AuthLogRow[]> {
  return fetchAndParse<AuthLogRow>('auth_logs.csv');
}

export async function loadDnsLogs(): Promise<DnsLogRow[]> {
  return fetchAndParse<DnsLogRow>('dns_logs.csv');
}

export async function loadFirewallLogs(): Promise<FirewallLogRow[]> {
  return fetchAndParse<FirewallLogRow>('firewall_logs.csv');
}

export async function loadMalwareAlerts(): Promise<MalwareAlertRow[]> {
  return fetchAndParse<MalwareAlertRow>('malware_alerts.csv');
}

/**
 * Parse a single CSV File with PapaParse (async).
 */
export function parseCsvFile<T>(file: File): Promise<T[]> {
  return new Promise((resolve, reject) => {
    Papa.parse<T>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        if (results.errors.length > 0) {
          reject(new Error(results.errors.map((e) => e.message).join('; ')));
        } else {
          resolve(results.data);
        }
      },
    });
  });
}

export type CsvFileSet = {
  auth: File;
  dns: File;
  firewall: File;
  malware: File;
};

/**
 * Parse the 4 CSV files from File objects. Order: auth, dns, firewall, malware.
 */
export async function loadFromFiles(
  files: CsvFileSet
): Promise<[AuthLogRow[], DnsLogRow[], FirewallLogRow[], MalwareAlertRow[]]> {
  const [auth, dns, firewall, malware] = await Promise.all([
    parseCsvFile<AuthLogRow>(files.auth),
    parseCsvFile<DnsLogRow>(files.dns),
    parseCsvFile<FirewallLogRow>(files.firewall),
    parseCsvFile<MalwareAlertRow>(files.malware),
  ]);
  return [auth, dns, firewall, malware];
}

/**
 * Combine all log arrays into a single NormalizedEvent[] sorted by time ascending.
 * Events with unparseable timestamps are placed at epoch (start of list).
 */
export function normalizeAllLogs(
  auth: AuthLogRow[],
  dns: DnsLogRow[],
  firewall: FirewallLogRow[],
  malware: MalwareAlertRow[]
): NormalizedEvent[] {
  const events: NormalizedEvent[] = [];

  for (const row of auth) {
    events.push({
      time: parseTimestamp(row.timestamp),
      source: 'auth',
      entity_ip: row.source_ip,
      user: row.user,
      action: row.action,
      raw: row,
    });
  }

  for (const row of dns) {
    events.push({
      time: parseTimestamp(row.timestamp),
      source: 'dns',
      entity_ip: row.client_ip,
      domain: row.domain_queried,
      raw: row,
    });
  }

  for (const row of firewall) {
    const port = row.destination_port != null && row.destination_port !== ''
      ? parseInt(row.destination_port, 10)
      : undefined;
    events.push({
      time: parseTimestamp(row.timestamp),
      source: 'firewall',
      entity_ip: row.source_ip,
      destination_ip: row.destination_ip,
      destination_port: Number.isFinite(port) ? port : undefined,
      action: row.action,
      raw: row,
    });
  }

  for (const row of malware) {
    events.push({
      time: parseTimestamp(row.timestamp),
      source: 'malware',
      hostname: row.hostname,
      raw: row,
    });
  }

  events.sort((a, b) => a.time.getTime() - b.time.getTime());
  return events;
}

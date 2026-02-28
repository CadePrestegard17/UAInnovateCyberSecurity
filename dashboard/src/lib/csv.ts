/**
 * Re-exports for backward compatibility. Prefer importing from:
 * - ./types for AuthLogRow, DnsLogRow, FirewallLogRow, MalwareAlertRow, NormalizedEvent
 * - ./parseCsv for loadAuthLogs, loadDnsLogs, loadFirewallLogs, loadMalwareAlerts, normalizeAllLogs
 * - ./time for parseTimestamp, parseTimestampOrUndefined
 */
export type { AuthLogRow, DnsLogRow, FirewallLogRow, MalwareAlertRow, NormalizedEvent, LogSource } from './types';
export {
  loadAuthLogs,
  loadDnsLogs,
  loadFirewallLogs,
  loadMalwareAlerts,
  normalizeAllLogs,
  loadFromFiles,
  parseCsvFile,
} from './parseCsv';
export type { CsvFileSet } from './parseCsv';

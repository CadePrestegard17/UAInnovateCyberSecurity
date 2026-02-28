/**
 * Row types for each CSV schema (columns match CSV headers).
 */
export interface AuthLogRow {
  timestamp: string;
  user: string;
  source_ip: string;
  action: string;
}

export interface DnsLogRow {
  timestamp: string;
  client_ip: string;
  domain_queried: string;
}

export interface FirewallLogRow {
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  destination_port: string;
  action: string;
}

export interface MalwareAlertRow {
  timestamp: string;
  hostname: string;
  threat_name: string;
}

export type LogSource = 'auth' | 'dns' | 'firewall' | 'malware';

/**
 * Normalized event used for unified timeline / analysis.
 * Optional fields depend on source.
 */
export interface NormalizedEvent {
  time: Date;
  source: LogSource;
  entity_ip?: string;
  user?: string;
  hostname?: string;
  domain?: string;
  destination_ip?: string;
  destination_port?: number;
  action?: string;
  raw: AuthLogRow | DnsLogRow | FirewallLogRow | MalwareAlertRow;
}

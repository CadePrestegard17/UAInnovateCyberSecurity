import { parseISO, isValid } from 'date-fns';

/**
 * Parse a timestamp string from the CSV logs into a Date.
 * Handles ISO 8601 (e.g. 2025-10-22T08:00:05) and strips leading/trailing whitespace.
 * Returns invalid Date if parsing fails (caller can check with isValid()).
 */
export function parseTimestamp(value: string): Date {
  if (value == null || typeof value !== 'string') return new Date(NaN);
  const trimmed = value.trim();
  if (trimmed === '') return new Date(NaN);
  const d = parseISO(trimmed);
  return d;
}

/**
 * Parse a timestamp and return a Date, or undefined if invalid.
 */
export function parseTimestampOrUndefined(value: string): Date | undefined {
  const d = parseTimestamp(value);
  return isValid(d) ? d : undefined;
}

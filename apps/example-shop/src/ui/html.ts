/** HTML escaping for every interpolated value. Never skip this. */
export function esc(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Formats a unix-seconds timestamp as a readable UTC string. */
export function formatTime(at: number): string {
  return new Date(at * 1000).toUTCString().replace(' GMT', ' UTC');
}

export function formatDate(at: number): string {
  return new Date(at * 1000).toISOString().slice(0, 10);
}

import { useState } from 'react';

const SECTIONS = [
  {
    title: 'Auth logs',
    body: 'Authentication events (logins). Success and denied/failed attempts per user and source IP. Use to spot brute-force or credential stuffing.',
  },
  {
    title: 'DNS logs',
    body: 'DNS queries: which client IP asked for which domain. Repeated queries to the same domain from one host can indicate beaconing or C2.',
  },
  {
    title: 'Firewall logs',
    body: 'Network flow: source IP, destination IP:port, and action (Allow/Deny). Use to see outbound connections and blocklists.',
  },
  {
    title: 'Malware alerts',
    body: 'Endpoint detections: hostname and threat name. Correlate with auth/DNS/firewall by time to link compromise to activity.',
  },
];

export function HowToUse() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <div className="how-to-use">
      <h2 className="how-to-use__title">How to use</h2>
      <div className="how-to-use__accordion">
        {SECTIONS.map((section, i) => (
          <div key={i} className="how-to-use__item">
            <button
              type="button"
              className="how-to-use__trigger"
              onClick={() => setOpenIndex(openIndex === i ? null : i)}
              aria-expanded={openIndex === i}
            >
              {section.title}
              <span className="how-to-use__chevron">{openIndex === i ? '▼' : '▶'}</span>
            </button>
            {openIndex === i && (
              <div className="how-to-use__body">{section.body}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

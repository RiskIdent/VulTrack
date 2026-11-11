import { useEffect, useState } from 'react';
import { BellRing, Save, Send } from 'lucide-react';
import { getSettings, sendStaleServerEmail, updateSettings } from '../api/client';

const KEYS = {
  hours: 'stale_server_hours',
  emailEnabled: 'stale_server_email_enabled',
  emailTo: 'stale_server_email_recipients',
  emailHour: 'stale_server_email_hour',
};

// StaleServerSettings configures the warning for servers without agent
// reports and the optional daily email.
export default function StaleServerSettings({ onSaved }: { onSaved?: () => void }) {
  const [hours, setHours] = useState('24');
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [emailTo, setEmailTo] = useState('');
  const [emailHour, setEmailHour] = useState('8');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    getSettings()
      .then(({ settings }) => {
        const get = (k: string) => settings.find((s) => s.key === k)?.value;
        setHours(get(KEYS.hours) ?? '24');
        setEmailEnabled(get(KEYS.emailEnabled) === 'true');
        setEmailTo(get(KEYS.emailTo) ?? '');
        setEmailHour(get(KEYS.emailHour) ?? '8');
      })
      .catch(() => undefined);
  }, []);

  const save = async () => {
    const h = parseInt(hours, 10);
    const eh = parseInt(emailHour, 10);
    if (isNaN(h) || h < 0) {
      setMessage({ ok: false, text: 'The threshold must be 0 or more hours.' });
      return;
    }
    if (isNaN(eh) || eh < 0 || eh > 23) {
      setMessage({ ok: false, text: 'The hour must be between 0 and 23.' });
      return;
    }
    if (emailEnabled && !emailTo.includes('@')) {
      setMessage({ ok: false, text: 'Enter at least one recipient for the email.' });
      return;
    }
    setSaving(true);
    try {
      await updateSettings({
        [KEYS.hours]: String(h),
        [KEYS.emailEnabled]: String(emailEnabled),
        [KEYS.emailTo]: emailTo.trim(),
        [KEYS.emailHour]: String(eh),
      });
      setMessage({ ok: true, text: 'Saved.' });
      onSaved?.();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : 'Failed to save' });
    } finally {
      setSaving(false);
    }
  };

  const sendNow = async () => {
    try {
      const r = await sendStaleServerEmail();
      setMessage({ ok: true, text: r.message });
    } catch (err) {
      setMessage({ ok: false, text: err instanceof Error ? err.message : 'Failed to send' });
    }
  };

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <BellRing className="w-5 h-5 text-[#4ade80]" />
        <h3 className="text-lg font-semibold text-[#e8f5e9]">Servers without agent report</h3>
      </div>
      <p className="text-sm text-[#6b7280] mb-4">
        A server whose agent has not reported for longer than the threshold is flagged in the server list, on the dashboard and on its
        page, and counted in Prometheus (<span className="font-mono">vultrack_servers_stale</span>). Disabled servers are never flagged.
      </p>
      <div className="space-y-4">
        <label className="flex items-center gap-3">
          <input type="number" min="0" step="1" value={hours} onChange={(e) => setHours(e.target.value)} className="input w-24" />
          <span className="text-sm text-[#e8f5e9]">hours without report until a server is flagged <span className="text-[#6b7280]">(0 = off)</span></span>
        </label>
        <label className="flex items-start gap-3 cursor-pointer">
          <input type="checkbox" checked={emailEnabled} onChange={(e) => setEmailEnabled(e.target.checked)} className="w-4 h-4 mt-1" />
          <div>
            <div className="text-[#e8f5e9]">Daily email</div>
            <div className="text-xs text-[#6b7280]">
              Lists the flagged servers once a day from the hour below. Sent only when at least one server is flagged; needs SMTP.
            </div>
          </div>
        </label>
        {emailEnabled && (
          <div className="flex flex-wrap items-end gap-4 pl-7">
            <label className="flex-1 min-w-64">
              <div className="text-sm text-[#a5d6a7] mb-1">Recipients (comma-separated)</div>
              <input type="text" value={emailTo} onChange={(e) => setEmailTo(e.target.value)} className="input w-full" placeholder="ops@example.com" />
            </label>
            <label>
              <div className="text-sm text-[#a5d6a7] mb-1">From hour (0–23)</div>
              <input type="number" min="0" max="23" value={emailHour} onChange={(e) => setEmailHour(e.target.value)} className="input w-24" />
            </label>
          </div>
        )}
        <div className="flex items-center gap-3">
          <button onClick={save} disabled={saving} className="btn btn-primary flex items-center gap-2">
            <Save className="w-4 h-4" /> Save
          </button>
          {emailEnabled && (
            <button onClick={sendNow} className="btn flex items-center gap-2 bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36]"
              title="Send the email now if any server is flagged (uses the saved settings)">
              <Send className="w-4 h-4" /> Send now
            </button>
          )}
          {message && <span className={`text-sm ${message.ok ? 'text-[#4ade80]' : 'text-red-400'}`}>{message.text}</span>}
        </div>
      </div>
    </div>
  );
}

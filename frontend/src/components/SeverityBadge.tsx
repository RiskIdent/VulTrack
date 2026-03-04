import { clsx } from 'clsx';

interface SeverityBadgeProps {
  severity: string;
  score?: number | null;
  className?: string;
}

// Calculate severity from CVSS score
function getSeverityFromScore(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

const severityClasses: Record<string, string> = {
  critical: 'bg-red-600/20 text-red-400 border-red-600/50',
  high: 'bg-orange-600/20 text-orange-400 border-orange-600/50',
  medium: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/50',
  low: 'bg-green-600/20 text-green-400 border-green-600/50',
  none: 'bg-gray-600/20 text-gray-400 border-gray-600/50',
};

// Original badge that uses vendor severity for color
export default function SeverityBadge({ severity, score, className }: SeverityBadgeProps) {
  const severityClass = severityClasses[severity?.toLowerCase()] || severityClasses.none;

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border',
        severityClass,
        className
      )}
    >
      <span className="uppercase">{severity || 'Unknown'}</span>
      {score !== null && score !== undefined && (
        <span className="opacity-75">({score.toFixed(1)})</span>
      )}
    </span>
  );
}

// CVSS Score badge - color based on score, not vendor severity
// Links to NVD when cveId is provided
export function CVSSBadge({ score, cveId, className }: { score: number | null; cveId?: string; className?: string }) {
  if (score === null || score === undefined) {
    return <span className="text-[#6b7280]">-</span>;
  }

  const calculatedSeverity = getSeverityFromScore(score);
  const severityClass = severityClasses[calculatedSeverity];

  const badge = (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold border',
        severityClass,
        cveId && 'cursor-pointer hover:opacity-80 transition-opacity',
        className
      )}
    >
      <span>{score.toFixed(1)}</span>
      <span className="uppercase opacity-90">{calculatedSeverity}</span>
    </span>
  );

  if (cveId) {
    return (
      <a 
        href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
        target="_blank"
        rel="noopener noreferrer"
        title="View on NVD"
      >
        {badge}
      </a>
    );
  }

  return badge;
}

// Vendor severity badge - just shows the vendor's assessment
// Links to vendor page when sourceLink is provided
export function VendorSeverityBadge({ severity, sourceLink, className }: { severity: string; sourceLink?: string; className?: string }) {
  if (!severity) {
    return <span className="text-[#6b7280]">-</span>;
  }

  const severityClass = severityClasses[severity?.toLowerCase()] || severityClasses.none;

  const badge = (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border',
        severityClass,
        sourceLink && 'cursor-pointer hover:opacity-80 transition-opacity',
        className
      )}
    >
      {severity.toUpperCase()}
    </span>
  );

  if (sourceLink) {
    return (
      <a 
        href={sourceLink}
        target="_blank"
        rel="noopener noreferrer"
        title="View vendor advisory"
      >
        {badge}
      </a>
    );
  }

  return badge;
}

// FixStateBadge displays the fix state with appropriate color coding
export function FixStateBadge({ fixState }: { fixState?: string }) {
  if (!fixState) {
    return <span className="text-[#6b7280]">-</span>;
  }

  const config: Record<string, { label: string; className: string; title: string }> = {
    fix_available: {
      label: 'Fix Available',
      className: 'bg-green-600/20 text-green-400',
      title: 'A fix is available from the vendor',
    },
    affected: {
      label: 'Affected',
      className: 'bg-yellow-600/20 text-yellow-400',
      title: 'Affected, no fix available yet',
    },
    will_not_fix: {
      label: 'Won\'t Fix',
      className: 'bg-orange-600/20 text-orange-400',
      title: 'Vendor has decided not to fix this issue',
    },
    deferred: {
      label: 'Deferred',
      className: 'bg-gray-600/20 text-gray-400',
      title: 'Vendor has deferred fixing this issue',
    },
  };

  const c = config[fixState] || {
    label: fixState,
    className: 'bg-blue-600/20 text-blue-400',
    title: fixState,
  };

  return (
    <span
      className={`px-2 py-1 rounded text-xs font-medium ${c.className}`}
      title={c.title}
    >
      {c.label}
    </span>
  );
}

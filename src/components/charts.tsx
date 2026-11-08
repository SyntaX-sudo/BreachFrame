import { useState } from 'react';
import { riskBand, SEVERITY_LABEL, SEVERITY_VAR } from '../lib/format';
import { SEVERITIES, type Severity } from '../lib/types';

/** Severity donut. Pure SVG, values are real counts. */
export function SeverityDonut({ counts, size = 148, label = 'open' }: { counts: Partial<Record<Severity, number>>; size?: number; label?: string }) {
  const [hover, setHover] = useState<Severity | null>(null);
  const total = SEVERITIES.reduce((s, k) => s + (counts[k] ?? 0), 0);
  const r = size / 2 - 12;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const shown = hover ? counts[hover] ?? 0 : total;
  return (
    <div className="flex items-center gap-5">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${total} findings by severity`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-line)" strokeWidth={14} />
        {total > 0 &&
          SEVERITIES.map((s) => {
            const v = counts[s] ?? 0;
            if (!v) return null;
            const len = (v / total) * c;
            const seg = (
              <circle
                key={s}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={SEVERITY_VAR[s]}
                strokeWidth={hover === s ? 17 : 14}
                strokeDasharray={`${Math.max(len - 2, 0.5)} ${c - Math.max(len - 2, 0.5)}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                style={{ transition: 'stroke-width 120ms', cursor: 'pointer' }}
                onMouseEnter={() => setHover(s)}
                onMouseLeave={() => setHover(null)}
              />
            );
            offset += len;
            return seg;
          })}
        <text x="50%" y="47%" textAnchor="middle" fill="var(--color-text)" fontSize={26} fontWeight={600}>
          {shown}
        </text>
        <text x="50%" y="62%" textAnchor="middle" fill="var(--color-muted)" fontSize={10.5} letterSpacing=".08em">
          {(hover ? SEVERITY_LABEL[hover] : label).toUpperCase()}
        </text>
      </svg>
      <ul className="space-y-1.5 text-[12px]">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center gap-2" onMouseEnter={() => setHover(s)} onMouseLeave={() => setHover(null)}>
            <span className="size-2 rounded-sm" style={{ background: SEVERITY_VAR[s] }} />
            <span className="w-16 text-[var(--color-muted)]">{SEVERITY_LABEL[s]}</span>
            <span className="tabular-nums font-medium">{counts[s] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export interface TrendPoint {
  id: number;
  label: string;
  value: number;
  sub?: string;
}

/** Risk score over successive analyses (bars). */
export function RiskBars({ points, height = 140, onSelect }: { points: TrendPoint[]; height?: number; onSelect?: (p: TrendPoint) => void }) {
  const [hover, setHover] = useState<number | null>(null);
  if (points.length === 0) return <div className="flex h-full items-center justify-center text-[12px] text-[var(--color-faint)]">No analyses yet</div>;
  const h = height - 22;
  const hp = hover != null ? points[hover] : points[points.length - 1];
  return (
    <div>
      <div className="mb-2 flex items-baseline gap-2 text-[12px]">
        <span className="text-[20px] font-semibold tabular-nums" style={{ color: riskBand(hp.value).color }}>
          {hp.value}
        </span>
        <span className="text-[var(--color-muted)]">{hp.label}</span>
        {hp.sub && <span className="truncate text-[var(--color-faint)]">· {hp.sub}</span>}
      </div>
      <div className="relative flex items-end gap-[3px]" style={{ height: h }} role="img" aria-label="Risk score per analysis">
        {[25, 50, 75].map((g) => (
          <div key={g} className="pointer-events-none absolute inset-x-0 border-t border-dashed border-[var(--color-line)]" style={{ bottom: `${g}%` }} />
        ))}
        {points.map((p, i) => (
          <button
            key={p.id}
            className="relative flex-1 rounded-t-[3px] transition-opacity"
            style={{
              height: `${Math.max(p.value, 1.5)}%`,
              maxWidth: 28,
              background: riskBand(p.value).color,
              opacity: hover == null || hover === i ? 0.95 : 0.35,
            }}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
            onClick={() => onSelect?.(p)}
            aria-label={`${p.label}: risk ${p.value}`}
          />
        ))}
      </div>
    </div>
  );
}

export function HBars({ rows, color = 'var(--color-accent)' }: { rows: { label: string; value: number; color?: string }[]; color?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  if (rows.length === 0) return <div className="py-6 text-center text-[12px] text-[var(--color-faint)]">Nothing to show</div>;
  return (
    <ul className="space-y-2">
      {rows.map((r) => (
        <li key={r.label} className="grid grid-cols-[110px_1fr_32px] items-center gap-3 text-[12px]">
          <span className="truncate font-mono text-[11px] text-[var(--color-muted)]" title={r.label}>
            {r.label}
          </span>
          <span className="h-2 overflow-hidden rounded-full bg-[var(--color-panel-2)]">
            <span className="block h-full rounded-full transition-[width] duration-500" style={{ width: `${(r.value / max) * 100}%`, background: r.color ?? color }} />
          </span>
          <span className="text-right tabular-nums">{r.value}</span>
        </li>
      ))}
    </ul>
  );
}

export function RiskGauge({ score, size = 112 }: { score: number; size?: number }) {
  const band = riskBand(score);
  const r = size / 2 - 9;
  const c = Math.PI * r;
  return (
    <svg width={size} height={size / 2 + 14} viewBox={`0 0 ${size} ${size / 2 + 14}`} role="img" aria-label={`Risk score ${score} of 100`}>
      <path d={`M 9 ${size / 2} A ${r} ${r} 0 0 1 ${size - 9} ${size / 2}`} fill="none" stroke="var(--color-line)" strokeWidth={10} strokeLinecap="round" />
      <path
        d={`M 9 ${size / 2} A ${r} ${r} 0 0 1 ${size - 9} ${size / 2}`}
        fill="none"
        stroke={band.color}
        strokeWidth={10}
        strokeLinecap="round"
        strokeDasharray={`${(score / 100) * c} ${c}`}
        style={{ transition: 'stroke-dasharray 600ms ease' }}
      />
      <text x="50%" y={size / 2 - 4} textAnchor="middle" fill="var(--color-text)" fontSize={24} fontWeight={650}>
        {score}
      </text>
      <text x="50%" y={size / 2 + 11} textAnchor="middle" fill={band.color} fontSize={10} fontWeight={600} letterSpacing=".08em">
        {band.label.toUpperCase()}
      </text>
    </svg>
  );
}

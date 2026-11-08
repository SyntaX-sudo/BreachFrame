import { useEffect, useRef, type ReactNode } from 'react';
import {
  Bot,
  Boxes,
  Cloud,
  Database,
  Globe,
  KeyRound,
  Loader2,
  Network,
  Plug,
  Server,
  Shield,
  User,
  Users,
  Wrench,
  X,
  type LucideIcon,
} from 'lucide-react';
import { SEVERITY_LABEL, SEVERITY_VAR, STATUS_LABEL } from '../lib/format';
import type { FindingStatus, NodeKind, Severity } from '../lib/types';

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(' ');
}

const SEVERITY_SHORT: Record<Severity, string> = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  return (
    <span
      data-testid={`sev-${severity}`}
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-[1px] text-[10.5px] font-semibold uppercase tracking-wider"
      style={{
        color: SEVERITY_VAR[severity],
        background: `color-mix(in srgb, ${SEVERITY_VAR[severity]} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${SEVERITY_VAR[severity]} 35%, transparent)`,
      }}
    >
      <span className="size-1.5 rounded-full" style={{ background: SEVERITY_VAR[severity] }} />
      {compact ? SEVERITY_SHORT[severity] : SEVERITY_LABEL[severity]}
    </span>
  );
}

const STATUS_COLOR: Record<FindingStatus, string> = {
  open: 'var(--color-sev-high)',
  in_progress: 'var(--color-sev-low)',
  resolved: 'var(--color-ok)',
  accepted_risk: 'var(--color-sev-medium)',
  false_positive: 'var(--color-muted)',
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11.5px] text-[var(--color-muted)]">
      <span className="size-2 rounded-[3px]" style={{ background: STATUS_COLOR[status] }} />
      {STATUS_LABEL[status]}
    </span>
  );
}

const KIND_ICON: Record<NodeKind, LucideIcon> = {
  user: User,
  group: Users,
  role: Shield,
  service_account: Bot,
  service: Server,
  api: Globe,
  agent: Bot,
  mcp_server: Plug,
  tool: Wrench,
  resource: Database,
  secret: KeyRound,
  external: Cloud,
  other: Boxes,
};

export const KIND_COLOR: Record<NodeKind, string> = {
  user: '#7aa7ff',
  group: '#9b8cff',
  role: '#c58bff',
  service_account: '#5fd4ff',
  service: '#4fd1a5',
  api: '#3df5c8',
  agent: '#ffb86b',
  mcp_server: '#ff8fd0',
  tool: '#f5c542',
  resource: '#a3b1c6',
  secret: '#ff3b5c',
  external: '#ff8a3d',
  other: '#8b95a7',
};

export function KindIcon({ kind, size = 14 }: { kind: NodeKind; size?: number }) {
  const Icon = KIND_ICON[kind] ?? Network;
  return <Icon size={size} style={{ color: KIND_COLOR[kind] }} aria-hidden />;
}

export function Spinner({ size = 14, className }: { size?: number; className?: string }) {
  return <Loader2 size={size} className={cx('animate-spin text-[var(--color-accent)]', className)} aria-label="Loading" />;
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('skeleton', className)} />;
}

export function PageHeader({ title, subtitle, actions, icon }: { title: string; subtitle?: ReactNode; actions?: ReactNode; icon?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4 border-b border-[var(--color-line)] px-6 pb-4 pt-5">
      <div className="min-w-0">
        <div className="flex items-center gap-2.5">
          {icon}
          <h1 className="text-[19px] font-semibold tracking-tight">{title}</h1>
        </div>
        {subtitle && <div className="mt-1 text-[12.5px] text-[var(--color-muted)]">{subtitle}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Card({ title, actions, children, className, bodyClass }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={cx('panel flex min-w-0 flex-col', className)}>
      {(title || actions) && (
        <div className="flex items-center justify-between gap-2 border-b border-[var(--color-line)] px-4 py-2.5">
          <div className="label">{title}</div>
          {actions}
        </div>
      )}
      <div className={cx('min-h-0 flex-1', bodyClass ?? 'p-4')}>{children}</div>
    </section>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon && <div className="text-[var(--color-faint)]">{icon}</div>}
      <div className="text-[14px] font-medium">{title}</div>
      {children && <div className="max-w-md text-[12.5px] text-[var(--color-muted)]">{children}</div>}
      {action}
    </div>
  );
}

export function ErrorNote({ error }: { error?: string }) {
  if (!error) return null;
  return (
    <div role="alert" className="m-4 rounded-lg border border-[color-mix(in_srgb,var(--color-sev-critical)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-sev-critical)_8%,transparent)] px-4 py-3 text-[12.5px]">
      {error}
    </div>
  );
}

export function Stat({ label, value, hint, color }: { label: string; value: ReactNode; hint?: ReactNode; color?: string }) {
  return (
    <div className="panel px-4 py-3">
      <div className="label">{label}</div>
      <div className="mt-1 text-[26px] font-semibold tabular-nums tracking-tight" style={{ color }}>
        {value}
      </div>
      {hint && <div className="text-[11.5px] text-[var(--color-muted)]">{hint}</div>}
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>('input, textarea, select, button:not([data-close])');
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => {
      window.removeEventListener('keydown', onKey, true);
      prev?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6 backdrop-blur-[2px] animate-fade-in" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className={cx('panel flex max-h-[85vh] w-full flex-col shadow-2xl animate-slide-up', wide ? 'max-w-3xl' : 'max-w-md')}>
        <div className="flex items-center justify-between border-b border-[var(--color-line)] px-5 py-3">
          <h2 className="text-[14px] font-semibold">{title}</h2>
          <button data-close className="btn btn-ghost h-7 px-1.5" onClick={onClose} aria-label="Close">
            <X size={15} />
          </button>
        </div>
        <div className="min-h-0 overflow-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-[var(--color-line)] px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}

export function Confirm({ open, title, message, confirmLabel = 'Delete', onConfirm, onClose }: { open: boolean; title: string; message: ReactNode; confirmLabel?: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={title}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-danger"
            onClick={() => {
              onConfirm();
              onClose();
            }}
          >
            {confirmLabel}
          </button>
        </>
      }
    >
      <div className="text-[13px] text-[var(--color-muted)]">{message}</div>
    </Modal>
  );
}

export function Segmented<T extends string>({ value, options, onChange, size = 'md' }: { value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; size?: 'sm' | 'md' }) {
  return (
    <div className="inline-flex rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-bg)] p-0.5" role="tablist">
      {options.map((o) => (
        <button
          key={o.value}
          role="tab"
          aria-selected={o.value === value}
          onClick={() => onChange(o.value)}
          className={cx(
            'rounded-md px-2.5 font-medium transition-colors',
            size === 'sm' ? 'h-6 text-[11.5px]' : 'h-7 text-[12.5px]',
            o.value === value ? 'bg-[var(--color-panel-3)] text-[var(--color-text)]' : 'text-[var(--color-muted)] hover:text-[var(--color-text)]',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Chip({ active, onClick, children, color }: { active: boolean; onClick: () => void; children: ReactNode; color?: string }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-[11.5px] transition-colors',
        active ? 'border-[var(--color-accent-dim)] bg-[color-mix(in_srgb,var(--color-accent)_10%,transparent)] text-[var(--color-text)]' : 'border-[var(--color-line-strong)] text-[var(--color-muted)] hover:text-[var(--color-text)]',
      )}
    >
      {color && <span className="size-1.5 rounded-full" style={{ background: color }} />}
      {children}
    </button>
  );
}

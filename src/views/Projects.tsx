import { useState } from 'react';
import { ClipboardPaste, Eye, FileCode2, FolderKanban, FolderOpen, FolderPlus, Pencil, Play, Plug, Search, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import { useAction, useAsync } from '../lib/hooks';
import { useUi } from '../lib/store';
import { ARTIFACT_LABEL, bytes, dateTime, riskBand, timeAgo } from '../lib/format';
import type { ArtifactRow, ProjectSummary } from '../lib/types';
import { Card, Confirm, cx, EmptyState, ErrorNote, Modal, PageHeader, Skeleton, Spinner } from '../components/ui';
import { useImportFiles, useRunAnalysis } from './common';

function ProjectForm({ open, onClose, initial }: { open: boolean; onClose: () => void; initial?: ProjectSummary }) {
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const { run, busy } = useAction();
  const openProject = useUi((s) => s.openProject);
  const submit = async () => {
    const r = await run(() => (initial ? api.updateProject(initial.id, name, description) : api.createProject(name, description)), initial ? 'Project updated' : 'Project created');
    if (r) {
      if (!initial) openProject(r.id);
      onClose();
    }
  };
  return (
    <Modal
      open={open}
      onClose={onClose}
      title={initial ? 'Edit project' : 'New project'}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" disabled={!name.trim() || busy} onClick={submit}>
            {busy && <Spinner size={13} />} {initial ? 'Save' : 'Create'}
          </button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim()) submit();
        }}
      >
        <label className="block">
          <span className="label">Name</span>
          <input className="input mt-1 w-full" value={name} maxLength={120} onChange={(e) => setName(e.target.value)} placeholder="e.g. Production cluster audit" />
        </label>
        <label className="block">
          <span className="label">Description</span>
          <textarea className="input mt-1 w-full" rows={3} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Scope, owner, ticket…" />
        </label>
      </form>
    </Modal>
  );
}

function PasteModal({ projectId, open, onClose }: { projectId: number; open: boolean; onClose: () => void }) {
  const [name, setName] = useState('pasted.yaml');
  const [content, setContent] = useState('');
  const { run, busy } = useAction();
  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      title="Paste configuration"
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={!content.trim() || !name.trim() || busy}
            onClick={async () => {
              if (await run(() => api.importText(projectId, name, content), `Imported ${name}`)) {
                setContent('');
                onClose();
              }
            }}
          >
            Import
          </button>
        </>
      }
    >
      <p className="mb-3 text-[12px] text-[var(--color-muted)]">The text is validated and parsed as data only. Unsupported formats are rejected.</p>
      <input className="input mb-2 w-full" value={name} onChange={(e) => setName(e.target.value)} aria-label="File name" />
      <textarea className="input h-72 w-full font-mono text-[11.5px]" value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} aria-label="Content" placeholder="Paste YAML or JSON…" />
    </Modal>
  );
}

function DiscoverModal({ projectId, open, onClose }: { projectId: number; open: boolean; onClose: () => void }) {
  const found = useAsync(() => (open ? api.discoverMcpConfigs() : Promise.resolve([])), [open]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const importFiles = useImportFiles();
  return (
    <Modal
      open={open}
      onClose={onClose}
      wide
      title="Discover local MCP configurations"
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Close
          </button>
          <button
            className="btn btn-primary"
            disabled={picked.size === 0}
            onClick={async () => {
              await importFiles(projectId, [...picked]);
              setPicked(new Set());
              onClose();
            }}
          >
            Import {picked.size || ''}
          </button>
        </>
      }
    >
      <p className="mb-3 text-[12px] text-[var(--color-muted)]">
        BreachFrame checks the standard locations used by Claude Desktop, Claude Code, Cursor, VS Code, Windsurf and Gemini CLI on this OS. Files are only read if you import them, and nothing inside them is executed.
      </p>
      {found.loading && <Spinner />}
      {found.data?.length === 0 && <div className="py-6 text-center text-[12.5px] text-[var(--color-faint)]">No MCP configuration files found in standard locations.</div>}
      <ul className="space-y-1">
        {(found.data ?? []).map((f) => (
          <li key={f.path}>
            <label className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-2 hover:bg-[var(--color-panel-2)]">
              <input
                type="checkbox"
                checked={picked.has(f.path)}
                onChange={(e) =>
                  setPicked((s) => {
                    const n = new Set(s);
                    if (e.target.checked) n.add(f.path);
                    else n.delete(f.path);
                    return n;
                  })
                }
              />
              <span className="w-40 shrink-0 text-[12.5px] font-medium">{f.client}</span>
              <code className="flex-1 truncate text-[11px] text-[var(--color-muted)]" title={f.path}>
                {f.path}
              </code>
              <span className={cx('text-[11px]', f.size > 5 * 1024 * 1024 ? 'text-[var(--color-sev-critical)]' : 'text-[var(--color-faint)]')}>{bytes(f.size)}</span>
            </label>
          </li>
        ))}
      </ul>
    </Modal>
  );
}

function ArtifactViewer({ artifact, onClose }: { artifact: ArtifactRow | null; onClose: () => void }) {
  const content = useAsync(() => (artifact ? api.artifactContent(artifact.id) : Promise.resolve('')), [artifact?.id]);
  return (
    <Modal open={!!artifact} onClose={onClose} wide title={artifact?.name ?? ''}>
      <div className="mb-2 flex gap-4 text-[11px] text-[var(--color-muted)]">
        <span>{artifact && ARTIFACT_LABEL[artifact.kind]}</span>
        <span>{artifact && bytes(artifact.size)}</span>
        <code className="truncate">sha256 {artifact?.sha256}</code>
      </div>
      <pre className="max-h-[60vh] overflow-auto rounded-md border border-[var(--color-line)] bg-[var(--color-bg)] p-3 font-mono text-[11px] leading-relaxed">{content.data}</pre>
    </Modal>
  );
}

function ProjectDetail({ project }: { project: ProjectSummary }) {
  const artifacts = useAsync(() => api.listArtifacts(project.id), [project.id]);
  const analyses = useAsync(() => api.listAnalyses(project.id), [project.id]);
  const importFiles = useImportFiles();
  const runAnalysis = useRunAnalysis();
  const { run } = useAction();
  const openProject = useUi((s) => s.openProject);
  const selectAnalysis = useUi((s) => s.selectAnalysis);
  const [running, setRunning] = useState(false);
  const [paste, setPaste] = useState(false);
  const [discover, setDiscover] = useState(false);
  const [edit, setEdit] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [viewing, setViewing] = useState<ArtifactRow | null>(null);
  const [removing, setRemoving] = useState<ArtifactRow | null>(null);

  return (
    <div className="flex min-w-0 flex-1 flex-col overflow-auto">
      <PageHeader
        title={project.name}
        subtitle={project.description || `Created ${dateTime(project.createdAt)}`}
        actions={
          <>
            <button className="btn" onClick={() => setEdit(true)} title="Edit">
              <Pencil size={13} />
            </button>
            <button className="btn btn-danger" onClick={() => setConfirmDelete(true)} title="Delete project">
              <Trash2 size={13} />
            </button>
            <button
              className="btn btn-primary"
              disabled={running || (artifacts.data?.length ?? 0) === 0}
              onClick={async () => {
                setRunning(true);
                await runAnalysis(project.id);
                setRunning(false);
              }}
            >
              {running ? <Spinner size={13} className="text-[#04221b]" /> : <Play size={13} />} Run analysis
            </button>
          </>
        }
      />
      <div className="grid grid-cols-12 gap-4 p-6">
        <Card
          className="col-span-12 xl:col-span-7"
          title={`Artifacts (${artifacts.data?.length ?? 0})`}
          bodyClass="p-0"
          actions={
            <div className="flex gap-1.5">
              <button className="btn h-7" onClick={() => setDiscover(true)}>
                <Plug size={13} /> Discover MCP
              </button>
              <button className="btn h-7" onClick={() => setPaste(true)}>
                <ClipboardPaste size={13} /> Paste
              </button>
              <button className="btn h-7" onClick={() => importFiles(project.id)}>
                <FolderOpen size={13} /> Import files
              </button>
            </div>
          }
        >
          {artifacts.loading && !artifacts.data && <Skeleton className="m-4 h-20" />}
          {artifacts.data?.length === 0 && (
            <EmptyState icon={<FileCode2 size={30} />} title="No artifacts">
              Import BreachFrame environment files (YAML/JSON), Kubernetes RBAC manifests, AWS IAM policies or authorization details, and MCP client configurations. Files up to 5 MiB.
            </EmptyState>
          )}
          <table className="w-full text-[12.5px]">
            <tbody>
              {(artifacts.data ?? []).map((a) => (
                <tr key={a.id} className="group border-b border-[var(--color-line)] last:border-0">
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <FileCode2 size={14} className="text-[var(--color-muted)]" />
                      <span className="font-medium">{a.name}</span>
                    </div>
                    <code className="text-[10px] text-[var(--color-faint)]">{a.sha256.slice(0, 16)}…</code>
                  </td>
                  <td className="px-2 py-2.5 text-[var(--color-muted)]">{ARTIFACT_LABEL[a.kind]}</td>
                  <td className="px-2 py-2.5 tabular-nums text-[var(--color-muted)]">{bytes(a.size)}</td>
                  <td className="px-2 py-2.5 text-[11px] text-[var(--color-faint)]">{a.origin}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button className="btn btn-ghost h-7 px-1.5" onClick={() => setViewing(a)} aria-label={`View ${a.name}`}>
                      <Eye size={13} />
                    </button>
                    <button className="btn btn-ghost btn-danger h-7 px-1.5" onClick={() => setRemoving(a)} aria-label={`Remove ${a.name}`}>
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card className="col-span-12 xl:col-span-5" title={`Analysis history (${analyses.data?.length ?? 0})`} bodyClass="p-0">
          {analyses.data?.length === 0 && <div className="px-4 py-10 text-center text-[12.5px] text-[var(--color-faint)]">No analyses yet.</div>}
          <ul>
            {(analyses.data ?? []).map((a, i) => (
              <li key={a.id} className="flex items-center gap-3 border-b border-[var(--color-line)] px-4 py-2.5 last:border-0">
                <span className="grid size-9 place-items-center rounded-md text-[13px] font-semibold tabular-nums" style={{ color: riskBand(a.riskScore).color, background: `color-mix(in srgb, ${riskBand(a.riskScore).color} 12%, transparent)` }}>
                  {a.riskScore}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px]">
                    #{a.id} {a.label && <span className="text-[var(--color-muted)]">· {a.label}</span>} {i === 0 && <span className="ml-1 rounded bg-[var(--color-panel-3)] px-1.5 text-[10px] text-[var(--color-accent)]">latest</span>}
                  </div>
                  <div className="text-[11px] text-[var(--color-faint)]">
                    {timeAgo(a.createdAt)} · {a.critical}C {a.high}H {a.medium}M {a.low}L · {a.nodes} nodes
                  </div>
                </div>
                <button
                  className="btn h-7"
                  onClick={() => {
                    selectAnalysis(project.id, i === 0 ? null : a.id);
                    openProject(project.id, 'attack-paths');
                  }}
                >
                  Open
                </button>
                <button className="btn btn-ghost btn-danger h-7 px-1.5" aria-label={`Delete analysis ${a.id}`} onClick={() => run(() => api.deleteAnalysis(a.id), `Deleted analysis #${a.id}`)}>
                  <Trash2 size={13} />
                </button>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <PasteModal projectId={project.id} open={paste} onClose={() => setPaste(false)} />
      <DiscoverModal projectId={project.id} open={discover} onClose={() => setDiscover(false)} />
      <ArtifactViewer artifact={viewing} onClose={() => setViewing(null)} />
      {edit && <ProjectForm open onClose={() => setEdit(false)} initial={project} />}
      <Confirm
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        title="Delete project?"
        message={`“${project.name}” and all of its artifacts, analyses and findings will be permanently deleted from this machine.`}
        onConfirm={() => run(() => api.deleteProject(project.id), 'Project deleted')}
      />
      <Confirm
        open={!!removing}
        onClose={() => setRemoving(null)}
        title="Remove artifact?"
        message={`${removing?.name} will be removed from the project. Existing analyses keep their snapshot.`}
        confirmLabel="Remove"
        onConfirm={() => removing && run(() => api.removeArtifact(removing.id), `Removed ${removing.name}`)}
      />
    </div>
  );
}

export function ProjectsView() {
  const projects = useAsync(() => api.listProjects(), []);
  const active = useUi((s) => s.activeProjectId);
  const openProject = useUi((s) => s.openProject);
  const [creating, setCreating] = useState(false);
  const [q, setQ] = useState('');
  const list = (projects.data ?? []).filter((p) => p.name.toLowerCase().includes(q.toLowerCase()));
  const selected = projects.data?.find((p) => p.id === active);

  return (
    <div className="flex h-full min-h-0">
      <div className="flex w-[300px] shrink-0 flex-col border-r border-[var(--color-line)]">
        <div className="flex items-center gap-2 border-b border-[var(--color-line)] p-3">
          <div className="relative flex-1">
            <Search size={13} className="absolute left-2.5 top-2.5 text-[var(--color-faint)]" />
            <input className="input w-full pl-7" placeholder="Filter projects" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter projects" />
          </div>
          <button className="btn btn-primary px-2.5" onClick={() => setCreating(true)} aria-label="New project" data-testid="new-project">
            <FolderPlus size={14} />
          </button>
        </div>
        <ErrorNote error={projects.error} />
        <ul className="flex-1 overflow-auto p-2">
          {list.map((p) => (
            <li key={p.id}>
              <button
                onClick={() => openProject(p.id)}
                className={cx('flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-left', p.id === active ? 'bg-[var(--color-panel-3)]' : 'hover:bg-[var(--color-panel-2)]')}
              >
                <span className="grid size-8 shrink-0 place-items-center rounded-md text-[12px] font-semibold tabular-nums" style={{ color: p.latestRisk == null ? 'var(--color-faint)' : riskBand(p.latestRisk).color, background: 'var(--color-panel-2)' }}>
                  {p.latestRisk ?? '—'}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[12.5px] font-medium">{p.name}</span>
                  <span className="block text-[11px] text-[var(--color-faint)]">
                    {p.artifactCount} files · {p.openFindings} open · {timeAgo(p.updatedAt)}
                  </span>
                </span>
              </button>
            </li>
          ))}
          {projects.data?.length === 0 && <li className="px-3 py-8 text-center text-[12px] text-[var(--color-faint)]">No projects yet</li>}
        </ul>
      </div>
      {selected ? (
        <ProjectDetail key={selected.id} project={selected} />
      ) : (
        <div className="flex flex-1 items-center justify-center">
          <EmptyState
            icon={<FolderKanban size={40} />}
            title="Select or create a project"
            action={
              <button className="btn btn-primary" onClick={() => setCreating(true)}>
                <FolderPlus size={14} /> New project
              </button>
            }
          >
            A project groups the configuration files of one system or audit, and keeps the history of every analysis.
          </EmptyState>
        </div>
      )}
      {creating && <ProjectForm open onClose={() => setCreating(false)} />}
    </div>
  );
}

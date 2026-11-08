import { useMemo } from 'react';
import { hasBackend } from './lib/api';
import { useUi } from './lib/store';
import { useShortcuts } from './lib/shortcuts';
import { ActivityPanel, BackendMissing, CommandPalette, ShortcutsHelp, Sidebar, Toasts, TopBar } from './components/Shell';
import { useImportFiles, useRunAnalysis } from './views/common';
import { DashboardView } from './views/Dashboard';
import { ProjectsView } from './views/Projects';
import { AttackPathsView } from './views/AttackPaths';
import { PermissionsView } from './views/Permissions';
import { McpView } from './views/Mcp';
import { LabsView } from './views/Labs';
import { CompareView } from './views/Compare';
import { FindingsView } from './views/Findings';
import { ReportsView } from './views/Reports';
import { SettingsView } from './views/Settings';

function CurrentView() {
  const view = useUi((s) => s.view);
  const active = useUi((s) => s.activeProjectId);
  // Key project-scoped views by project so state resets when switching tabs.
  switch (view) {
    case 'dashboard':
      return <DashboardView />;
    case 'projects':
      return <ProjectsView />;
    case 'attack-paths':
      return <AttackPathsView key={active ?? 'none'} />;
    case 'permissions':
      return <PermissionsView key={active ?? 'none'} />;
    case 'mcp':
      return <McpView key={active ?? 'none'} />;
    case 'labs':
      return <LabsView />;
    case 'compare':
      return <CompareView key={active ?? 'none'} />;
    case 'findings':
      return <FindingsView key={active ?? 'none'} />;
    case 'reports':
      return <ReportsView key={active ?? 'none'} />;
    case 'settings':
      return <SettingsView />;
  }
}

function Workspace() {
  const ui = useUi();
  const importFiles = useImportFiles();
  const runAnalysis = useRunAnalysis();

  const handlers = useMemo(
    () => ({
      palette: () => ui.setPalette(true),
      view: ui.setView,
      newProject: () => {
        ui.setView('projects');
        setTimeout(() => document.querySelector<HTMLButtonElement>('[data-testid="new-project"]')?.click(), 50);
      },
      importFiles: () => {
        if (ui.activeProjectId != null) importFiles(ui.activeProjectId);
        else ui.toast({ kind: 'info', title: 'Open a project first' });
      },
      runAnalysis: () => {
        if (ui.activeProjectId != null) runAnalysis(ui.activeProjectId);
        else ui.toast({ kind: 'info', title: 'Open a project first' });
      },
      closeTab: () => ui.activeProjectId != null && ui.closeProject(ui.activeProjectId),
      nextTab: (dir: 1 | -1) => {
        const tabs = ui.openProjects;
        if (tabs.length === 0) return;
        const i = ui.activeProjectId != null ? tabs.indexOf(ui.activeProjectId) : -1;
        ui.setActiveProject(tabs[(i + dir + tabs.length) % tabs.length]);
      },
      toggleActivity: ui.toggleActivity,
      help: () => ui.setShortcuts(true),
    }),
    [ui, importFiles, runAnalysis],
  );
  useShortcuts(handlers);

  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <div className="flex min-h-0 flex-1">
          <main className="min-w-0 flex-1 overflow-hidden animate-fade-in" key={ui.view}>
            <CurrentView />
          </main>
          <ActivityPanel />
        </div>
      </div>
      <CommandPalette />
      <ShortcutsHelp />
      <Toasts />
    </div>
  );
}

export default function App() {
  if (!hasBackend()) return <BackendMissing />;
  return <Workspace />;
}

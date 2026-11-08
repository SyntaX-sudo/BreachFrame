import { create } from 'zustand';

export type View =
  | 'dashboard'
  | 'projects'
  | 'attack-paths'
  | 'permissions'
  | 'mcp'
  | 'labs'
  | 'compare'
  | 'findings'
  | 'reports'
  | 'settings';

export interface Toast {
  id: number;
  kind: 'success' | 'error' | 'info';
  title: string;
  detail?: string;
}

interface UiState {
  view: View;
  openProjects: number[];
  activeProjectId: number | null;
  /** Per-project pinned analysis (null = latest). */
  selectedAnalysis: Record<number, number | null>;
  activityOpen: boolean;
  paletteOpen: boolean;
  shortcutsOpen: boolean;
  toasts: Toast[];
  /** Incremented whenever backend data changes so views refetch. */
  revision: number;
  /** Finding to focus when opening the Findings view (engine fingerprint). */
  focusFinding: string | null;

  setView: (v: View) => void;
  openProject: (id: number, view?: View) => void;
  closeProject: (id: number) => void;
  setActiveProject: (id: number | null) => void;
  selectAnalysis: (projectId: number, analysisId: number | null) => void;
  toggleActivity: () => void;
  setPalette: (open: boolean) => void;
  setShortcuts: (open: boolean) => void;
  toast: (t: Omit<Toast, 'id'>) => void;
  dismissToast: (id: number) => void;
  bump: () => void;
  setFocusFinding: (id: string | null) => void;
}

let toastId = 0;

const PERSIST_KEY = 'breachframe.ui.v1';

function loadPersisted(): Partial<UiState> {
  try {
    const raw = localStorage.getItem(PERSIST_KEY);
    if (!raw) return {};
    const p = JSON.parse(raw);
    return {
      openProjects: Array.isArray(p.openProjects) ? p.openProjects.filter((n: unknown) => typeof n === 'number') : [],
      activeProjectId: typeof p.activeProjectId === 'number' ? p.activeProjectId : null,
      activityOpen: !!p.activityOpen,
    };
  } catch {
    return {};
  }
}

export const useUi = create<UiState>((set) => ({
  view: 'dashboard',
  openProjects: [],
  activeProjectId: null,
  selectedAnalysis: {},
  activityOpen: false,
  paletteOpen: false,
  shortcutsOpen: false,
  toasts: [],
  revision: 0,
  focusFinding: null,
  ...loadPersisted(),

  setView: (view) => set({ view }),
  openProject: (id, view) =>
    set((s) => ({
      openProjects: s.openProjects.includes(id) ? s.openProjects : [...s.openProjects, id],
      activeProjectId: id,
      view: view ?? s.view,
    })),
  closeProject: (id) =>
    set((s) => {
      const idx = s.openProjects.indexOf(id);
      const openProjects = s.openProjects.filter((p) => p !== id);
      const activeProjectId =
        s.activeProjectId === id ? (openProjects[Math.max(0, idx - 1)] ?? openProjects[0] ?? null) : s.activeProjectId;
      return { openProjects, activeProjectId };
    }),
  setActiveProject: (activeProjectId) => set({ activeProjectId }),
  selectAnalysis: (projectId, analysisId) =>
    set((s) => ({ selectedAnalysis: { ...s.selectedAnalysis, [projectId]: analysisId } })),
  toggleActivity: () => set((s) => ({ activityOpen: !s.activityOpen })),
  setPalette: (paletteOpen) => set({ paletteOpen }),
  setShortcuts: (shortcutsOpen) => set({ shortcutsOpen }),
  toast: (t) => {
    const id = ++toastId;
    set((s) => ({ toasts: [...s.toasts.slice(-4), { ...t, id }] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })), t.kind === 'error' ? 8000 : 4000);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),
  bump: () => set((s) => ({ revision: s.revision + 1 })),
  setFocusFinding: (focusFinding) => set({ focusFinding }),
}));

useUi.subscribe((s) => {
  try {
    localStorage.setItem(
      PERSIST_KEY,
      JSON.stringify({ openProjects: s.openProjects, activeProjectId: s.activeProjectId, activityOpen: s.activityOpen }),
    );
  } catch {
    /* storage unavailable */
  }
});

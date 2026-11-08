import { useEffect } from 'react';
import type { View } from './store';

export interface ShortcutHandlers {
  palette: () => void;
  view: (v: View) => void;
  newProject: () => void;
  importFiles: () => void;
  runAnalysis: () => void;
  closeTab: () => void;
  nextTab: (dir: 1 | -1) => void;
  toggleActivity: () => void;
  help: () => void;
}

const VIEW_KEYS: Record<string, View> = {
  '1': 'dashboard',
  '2': 'projects',
  '3': 'attack-paths',
  '4': 'permissions',
  '5': 'mcp',
  '6': 'labs',
  '7': 'compare',
  '8': 'findings',
  '9': 'reports',
};

function isTyping(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
}

/** Map a keyboard event to an action name. Exported for tests. */
export function matchShortcut(e: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'shiftKey' | 'altKey' | 'target'>): string | null {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && !e.altKey) {
    const k = e.key.toLowerCase();
    if (k === 'k') return 'palette';
    if (VIEW_KEYS[e.key] && !e.shiftKey) return `view:${VIEW_KEYS[e.key]}`;
    if (k === 'n' && !e.shiftKey) return 'newProject';
    if (k === 'i' && !e.shiftKey) return 'importFiles';
    if (k === 'enter') return 'runAnalysis';
    if (k === 'w') return 'closeTab';
    if (e.shiftKey && (e.key === ']' || e.key === '}')) return 'nextTab';
    if (e.shiftKey && (e.key === '[' || e.key === '{')) return 'prevTab';
    if (e.key === '.') return 'toggleActivity';
    return null;
  }
  if (!mod && !e.altKey && e.key === '?' && !isTyping(e.target)) return 'help';
  return null;
}

export function useShortcuts(h: ShortcutHandlers) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const action = matchShortcut(e);
      if (!action) return;
      e.preventDefault();
      if (action.startsWith('view:')) h.view(action.slice(5) as View);
      else if (action === 'nextTab') h.nextTab(1);
      else if (action === 'prevTab') h.nextTab(-1);
      else (h[action as keyof ShortcutHandlers] as () => void)();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [h]);
}

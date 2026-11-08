import { describe, expect, it } from 'vitest';
import { bytes, riskBand, timeAgo } from './format';
import { matchShortcut } from './shortcuts';
import { buildFilter } from '../views/Findings';

const key = (k: string, mods: Partial<{ ctrlKey: boolean; metaKey: boolean; shiftKey: boolean; altKey: boolean }> = {}, target: EventTarget | null = null) => ({
  key: k,
  ctrlKey: false,
  metaKey: false,
  shiftKey: false,
  altKey: false,
  target,
  ...mods,
});

describe('format', () => {
  it('formats relative time', () => {
    const now = 1_000_000_000;
    expect(timeAgo(now, now)).toBe('just now');
    expect(timeAgo(now - 90_000, now)).toBe('2m ago');
    expect(timeAgo(now - 3 * 3600_000, now)).toBe('3h ago');
  });
  it('formats bytes', () => {
    expect(bytes(512)).toBe('512 B');
    expect(bytes(2048)).toBe('2.0 KB');
    expect(bytes(5 * 1024 * 1024)).toBe('5.00 MB');
  });
  it('bands risk scores', () => {
    expect(riskBand(0).label).toBe('Clear');
    expect(riskBand(35).label).toBe('Elevated');
    expect(riskBand(55).label).toBe('High');
    expect(riskBand(90).label).toBe('Critical');
  });
});

describe('keyboard shortcuts', () => {
  it('maps modifier shortcuts', () => {
    expect(matchShortcut(key('k', { ctrlKey: true }))).toBe('palette');
    expect(matchShortcut(key('k', { metaKey: true }))).toBe('palette');
    expect(matchShortcut(key('3', { ctrlKey: true }))).toBe('view:attack-paths');
    expect(matchShortcut(key('Enter', { ctrlKey: true }))).toBe('runAnalysis');
    expect(matchShortcut(key(']', { ctrlKey: true, shiftKey: true }))).toBe('nextTab');
    expect(matchShortcut(key('.', { ctrlKey: true }))).toBe('toggleActivity');
  });
  it('ignores plain keys and help while typing', () => {
    expect(matchShortcut(key('k'))).toBeNull();
    expect(matchShortcut(key('?'))).toBe('help');
    const input = document.createElement('input');
    expect(matchShortcut(key('?', {}, input))).toBeNull();
  });
});

describe('findings filter', () => {
  it('builds the backend filter', () => {
    const f = buildFilter({
      projectOnly: true,
      projectId: 4,
      severities: new Set(['critical']),
      statuses: new Set(['open']),
      categories: new Set(),
      search: '  token ',
      history: false,
    });
    expect(f).toEqual({ projectId: 4, severities: ['critical'], statuses: ['open'], categories: [], search: 'token', includeAbsent: false });
    expect(buildFilter({ projectOnly: false, projectId: 4, severities: new Set(), statuses: new Set(), categories: new Set(), search: '', history: true }).projectId).toBeNull();
  });
});

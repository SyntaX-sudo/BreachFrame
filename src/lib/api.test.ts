import { describe, expect, it } from 'vitest';
import { mockIPC, mockWindows } from '@tauri-apps/api/mocks';
import { api, ApiError, hasBackend } from './api';

describe('IPC contract', () => {
  it('sends camelCase arguments to the expected commands', async () => {
    const calls: [string, unknown][] = [];
    mockIPC((cmd, args) => {
      calls.push([cmd, args]);
      if (cmd === 'run_analysis') return { analysis: { id: 7, riskScore: 35 }, newFindings: 1, resolvedFindings: 0, reopenedFindings: 0, artifactErrors: [] };
      if (cmd === 'list_findings') return [];
      if (cmd === 'update_finding') return { id: 3, status: 'resolved' };
      return null;
    });

    const r = await api.runAnalysis(12, 'nightly');
    expect(r.analysis.id).toBe(7);
    await api.listFindings({ projectId: 12, severities: ['critical'] });
    await api.updateFinding(3, { status: 'resolved' });
    await api.compareAnalyses(1, 2);
    await api.exportReport(5, 'html', '/tmp/r.html');

    expect(calls).toEqual([
      ['run_analysis', { projectId: 12, label: 'nightly' }],
      ['list_findings', { filter: { projectId: 12, severities: ['critical'] } }],
      ['update_finding', { id: 3, status: 'resolved', notes: null }],
      ['compare_analyses', { beforeId: 1, afterId: 2 }],
      ['export_report', { analysisId: 5, format: 'html', path: '/tmp/r.html' }],
    ]);
  });

  it('wraps backend errors in ApiError with the command name', async () => {
    mockIPC(() => {
      throw 'not found: project 99';
    });
    const err = await api.getProject(99).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.command).toBe('get_project');
    expect(err.message).toBe('not found: project 99');
  });

  it('detects the Tauri runtime', () => {
    mockWindows('main');
    expect(hasBackend()).toBe(true);
  });
});

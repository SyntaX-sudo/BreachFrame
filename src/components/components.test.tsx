import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SeverityBadge, StatusBadge, Segmented, Confirm } from './ui';
import { HBars, RiskGauge, SeverityDonut } from './charts';
import { BackendMissing } from './Shell';

describe('UI components', () => {
  it('renders severity and status badges', () => {
    render(
      <>
        <SeverityBadge severity="critical" />
        <StatusBadge status="accepted_risk" />
      </>,
    );
    expect(screen.getByTestId('sev-critical')).toHaveTextContent('Critical');
    expect(screen.getByText('Accepted risk')).toBeInTheDocument();
  });

  it('donut shows the real total and legend counts', () => {
    render(<SeverityDonut counts={{ critical: 2, high: 3, medium: 0, low: 1, info: 0 }} />);
    expect(screen.getByRole('img', { name: '6 findings by severity' })).toBeInTheDocument();
    const legend = screen.getByRole('list');
    expect(within(legend).getByText('Critical').nextSibling).toHaveTextContent('2');
  });

  it('gauge reports the score accessibly', () => {
    render(<RiskGauge score={84} />);
    expect(screen.getByRole('img', { name: 'Risk score 84 of 100' })).toHaveTextContent('CRITICAL');
  });

  it('bars render rows and an empty state', () => {
    const { rerender } = render(<HBars rows={[{ label: 'MCP-001', value: 3 }]} />);
    expect(screen.getByText('MCP-001')).toBeInTheDocument();
    rerender(<HBars rows={[]} />);
    expect(screen.getByText('Nothing to show')).toBeInTheDocument();
  });

  it('segmented control changes value', async () => {
    const onChange = vi.fn();
    render(
      <Segmented
        value="a"
        onChange={onChange}
        options={[
          { value: 'a', label: 'A' },
          { value: 'b', label: 'B' },
        ]}
      />,
    );
    expect(screen.getByRole('tab', { name: 'A' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.click(screen.getByRole('tab', { name: 'B' }));
    expect(onChange).toHaveBeenCalledWith('b');
  });

  it('confirm dialog runs the action and closes; Escape cancels', async () => {
    const onConfirm = vi.fn();
    const onClose = vi.fn();
    render(<Confirm open title="Delete?" message="Gone forever" onConfirm={onConfirm} onClose={onClose} />);
    expect(screen.getByRole('dialog', { name: 'Delete?' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalled();
  });

  it('never shows fake data without a backend', () => {
    render(<BackendMissing />);
    expect(screen.getByText(/backend not detected/i)).toBeInTheDocument();
    expect(screen.getByText(/No simulated data is ever displayed/)).toBeInTheDocument();
  });
});

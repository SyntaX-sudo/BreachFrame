import { memo, useEffect, useMemo } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge as RFEdge,
  type Node as RFNode,
  type NodeProps,
} from '@xyflow/react';
import { edgeLabel, isSensitive, layoutGraph } from '../lib/graph';
import { KIND_LABEL } from '../lib/format';
import type { Graph, GraphNode } from '../lib/types';
import { cx, KIND_COLOR, KindIcon } from './ui';

export type NodeState = 'hot' | 'sim' | 'dim' | 'added' | 'removed' | 'start' | undefined;

interface NodeData extends Record<string, unknown> {
  node: GraphNode;
  state: NodeState;
  selected: boolean;
}

const SecurityNode = memo(function SecurityNode({ data }: NodeProps<RFNode<NodeData>>) {
  const { node, state, selected } = data;
  const color = KIND_COLOR[node.kind];
  const sensitive = isSensitive(node);
  return (
    <div
      className={cx(
        'flex h-[52px] w-[196px] items-center gap-2.5 rounded-[9px] border bg-[var(--color-panel)] px-2.5 transition-all duration-200',
        state === 'dim' && 'opacity-25',
        selected && 'ring-2 ring-[var(--color-accent)]',
        state === 'start' && 'animate-pulse-ring',
      )}
      style={{
        borderColor:
          state === 'hot' || state === 'start'
            ? 'var(--color-sev-critical)'
            : state === 'sim'
              ? 'var(--color-sev-high)'
              : state === 'added'
                ? 'var(--color-ok)'
                : state === 'removed'
                  ? 'var(--color-sev-critical)'
                  : 'var(--color-line-strong)',
        boxShadow: state === 'hot' ? '0 0 0 1px var(--color-sev-critical), 0 0 18px -4px rgb(255 59 92 / .6)' : undefined,
        borderStyle: state === 'removed' ? 'dashed' : 'solid',
      }}
      title={`${KIND_LABEL[node.kind]} · ${node.id}`}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5 !border-0 !bg-[var(--color-line-strong)]" />
      <div className="grid size-7 shrink-0 place-items-center rounded-md" style={{ background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
        <KindIcon kind={node.kind} size={14} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[11.5px] font-medium leading-tight">{node.label || node.id}</div>
        <div className="truncate text-[9.5px] uppercase tracking-wider text-[var(--color-faint)]">{KIND_LABEL[node.kind]}</div>
      </div>
      {sensitive && <span className="size-1.5 shrink-0 rounded-full bg-[var(--color-sev-critical)]" title="Sensitive" />}
      <Handle type="source" position={Position.Right} className="!size-1.5 !border-0 !bg-[var(--color-line-strong)]" />
    </div>
  );
});

const nodeTypes = { security: SecurityNode };

export interface GraphViewProps {
  graph: Graph;
  nodeState?: (id: string) => NodeState;
  edgeClass?: (id: string) => string | undefined;
  selected?: string | null;
  onSelect?: (id: string | null) => void;
  showLabels?: boolean;
  /** Change this value to re-fit the viewport. */
  fitKey?: unknown;
  minimap?: boolean;
}

function Inner({ graph, nodeState, edgeClass, selected, onSelect, showLabels = true, fitKey, minimap = true }: GraphViewProps) {
  const layout = useMemo(() => layoutGraph(graph), [graph]);
  const { fitView } = useReactFlow();

  const nodes: RFNode<NodeData>[] = useMemo(
    () =>
      graph.nodes.map((n) => {
        const p = layout.get(n.id)!;
        return {
          id: n.id,
          type: 'security',
          position: { x: p.x, y: p.y },
          data: { node: n, state: nodeState?.(n.id), selected: selected === n.id },
          draggable: true,
        };
      }),
    [graph, layout, nodeState, selected],
  );

  const edges: RFEdge[] = useMemo(
    () =>
      graph.edges.map((e) => {
        const cls = edgeClass?.(e.id);
        const hot = cls === 'edge-hot' || cls === 'edge-sim' || cls === 'edge-added';
        return {
          id: e.id,
          source: e.from,
          target: e.to,
          label: showLabels || hot ? edgeLabel(e) : undefined,
          className: cls,
          animated: hot,
          markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: hot ? '#ff3b5c' : '#3a4866' },
          labelBgPadding: [4, 2] as [number, number],
          labelStyle: { fill: hot ? 'var(--color-text)' : 'var(--color-muted)' },
        };
      }),
    [graph, edgeClass, showLabels],
  );

  useEffect(() => {
    const t = setTimeout(() => fitView({ padding: 0.15, duration: 300 }), 30);
    return () => clearTimeout(t);
  }, [fitKey, graph, fitView]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onNodeClick={(_, n) => onSelect?.(n.id)}
      onPaneClick={() => onSelect?.(null)}
      minZoom={0.1}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      nodesConnectable={false}
      fitView
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#1f2838" />
      <Controls showInteractive={false} position="bottom-left" />
      {minimap && graph.nodes.length > 12 && (
        <MiniMap pannable zoomable nodeColor={(n) => KIND_COLOR[(n.data as NodeData).node.kind]} nodeStrokeWidth={0} position="bottom-right" />
      )}
    </ReactFlow>
  );
}

export function GraphView(props: GraphViewProps) {
  return (
    <ReactFlowProvider>
      <Inner {...props} />
    </ReactFlowProvider>
  );
}

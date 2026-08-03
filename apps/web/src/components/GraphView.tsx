"use client";

import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphPayload } from "@/lib/types";

export function GraphView({ graph }: { graph: GraphPayload }) {
  const nodes: Node[] = graph.nodes.slice(0, 120).map((n, i) => ({
    id: n.id,
    position: {
      x: (i % 8) * 180,
      y: Math.floor(i / 8) * 110,
    },
    data: { label: n.label },
    style: {
      background: "#141b28",
      color: "#e6edf3",
      border: "1px solid #243041",
      borderRadius: 12,
      fontSize: 11,
      padding: 8,
      minWidth: 120,
    },
  }));

  const edges: Edge[] = graph.edges.slice(0, 200).map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label ?? undefined,
    style: { stroke: "#22d3ee", strokeOpacity: 0.55 },
    labelStyle: { fill: "#8b9bb0", fontSize: 10 },
  }));

  return (
    <div className="h-full min-h-[320px] w-full overflow-hidden rounded-xl border border-ink-600 bg-ink-950">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }}>
        <Background color="#243041" gap={18} />
        <MiniMap
          nodeColor="#22d3ee"
          maskColor="rgba(7,10,15,0.8)"
          style={{ background: "#0b0f14" }}
        />
        <Controls />
      </ReactFlow>
    </div>
  );
}

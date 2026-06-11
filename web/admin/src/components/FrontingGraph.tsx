// FrontingGraph — DAG view of fronting links.
//
// Two-column layout: Mint sources on the left (any Resource that appears
// as `source_slug` in any link), all targets on the right (any Resource
// that appears as `target_slug`). A Resource that acts as both is drawn
// in both columns. Edges are cubic Béziers from source-right to
// target-left; gray when the link's scope_map references keys/values
// that no longer exist in the current Resource scopes (drift).
//
// Badges:
//   red dot   — orphan target: target Resource has scopes that no link
//               value-list ever maps to.
//   yellow dot— unused source: Mint Resource has scopes that no link
//               key-set ever references.
//
// Click node → onNodeClick(slug) (caller navigates).
// Click edge → onEdgeClick(link) (caller opens drawer in edit mode).
// Scale: optimized for ≤10 links / ~15 resources (decision P1-A); a
// warning banner appears above 30 links / 50 resources to nudge the
// operator toward the List tab when the topology grows past the
// hand-rolled layout's comfort zone.

import { useMemo, useState } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import type { FrontingLinkView, ResourceView } from "../api";

interface FrontingGraphProps {
  links: FrontingLinkView[];
  resources: ResourceView[];
  onNodeClick: (slug: string) => void;
  onEdgeClick: (link: FrontingLinkView) => void;
}

interface NodeRect {
  slug: string;
  resource: ResourceView | null; // null = ghost (referenced but missing)
  side: "left" | "right";
  x: number;
  y: number;
  w: number;
  h: number;
  orphanTarget: boolean;
  unusedSource: boolean;
}

const NODE_W = 160;
const NODE_H = 44;
const COL_GAP = 240;
const ROW_GAP = 16;
const PAD_X = 20;
const PAD_Y = 20;

export default function FrontingGraph({
  links,
  resources,
  onNodeClick,
  onEdgeClick,
}: FrontingGraphProps) {
  const [hovered, setHovered] = useState<
    { kind: "node"; slug: string } | { kind: "edge"; key: string } | null
  >(null);

  const layout = useMemo(
    () => buildLayout(links, resources),
    [links, resources],
  );

  if (links.length === 0) {
    return (
      <div
        style={{
          padding: "40px 20px",
          textAlign: "center",
          color: C.textDim,
          fontSize: sz.base,
        }}
      >
        No fronting links yet. Switch to the List tab and click + New
        Fronting Link to create one.
      </div>
    );
  }

  const showScaleWarning = links.length > 30 || resources.length > 50;

  return (
    <div>
      {showScaleWarning && (
        <div
          style={{
            marginBottom: 12,
            padding: "6px 12px",
            background: alpha(C.warn, 0x12),
            border: `1px solid ${alpha(C.warn, 0x40)}`,
            borderRadius: 6,
            fontSize: sz.sm,
            color: C.warn,
          }}
        >
          Graph view is best for small topologies — switch to the List tab
          for full data.
        </div>
      )}
      <div
        style={{
          background: C.surface2,
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          overflow: "auto",
        }}
      >
        <svg
          width={layout.width}
          height={layout.height}
          style={{ display: "block" }}
        >
          {/* Edges first so nodes overlap them. */}
          {layout.edges.map((e) => {
            const isHovered =
              hovered?.kind === "edge" && hovered.key === e.key;
            // Always-visible label: edges are fronting links and the
            // label summarizes the scope map. Pill background keeps the
            // text readable when the edge crosses other graph elements;
            // hover bumps to accent color so the operator can confirm
            // which edge they're about to click.
            const label = edgeLabel(e.link, e.drifted);
            const labelW = Math.max(36, label.length * 7 + 12);
            return (
              <g key={e.key}>
                <path
                  d={e.path}
                  fill="none"
                  stroke={e.drifted ? C.textDim : C.border2}
                  strokeWidth={isHovered ? 2.5 : 1.5}
                  style={{ cursor: "pointer", transition: "stroke-width 0.1s" }}
                  onMouseEnter={() =>
                    setHovered({ kind: "edge", key: e.key })
                  }
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => onEdgeClick(e.link)}
                />
                <rect
                  x={e.midX - labelW / 2}
                  y={e.midY - 9}
                  width={labelW}
                  height={18}
                  rx={9}
                  fill={C.surface2}
                  stroke={isHovered ? alpha(C.accent, 0x50) : C.border2}
                  style={{ cursor: "pointer", pointerEvents: "all" }}
                  onMouseEnter={() => setHovered({ kind: "edge", key: e.key })}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => onEdgeClick(e.link)}
                />
                <text
                  x={e.midX}
                  y={e.midY + 4}
                  textAnchor="middle"
                  fontFamily={fonts.mono}
                  fontSize={11}
                  fill={isHovered ? C.accent : C.textDim}
                  style={{ pointerEvents: "none" }}
                >
                  {label}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {layout.nodes.map((n) => {
            const isGhost = n.resource === null;
            const isHovered =
              hovered?.kind === "node" && hovered.slug === n.slug;
            return (
              <g
                key={`${n.side}-${n.slug}`}
                style={{ cursor: "pointer" }}
                onMouseEnter={() =>
                  setHovered({ kind: "node", slug: n.slug })
                }
                onMouseLeave={() => setHovered(null)}
                onClick={() => onNodeClick(n.slug)}
              >
                <rect
                  x={n.x}
                  y={n.y}
                  width={n.w}
                  height={n.h}
                  rx={6}
                  fill={isHovered ? alpha(C.accent, 0x12) : C.surface}
                  stroke={
                    isGhost
                      ? C.danger
                      : isHovered
                        ? C.accent
                        : C.border2
                  }
                  strokeDasharray={isGhost ? "4,3" : undefined}
                  strokeWidth={1.5}
                />
                <text
                  x={n.x + 10}
                  y={n.y + 18}
                  fontFamily={fonts.mono}
                  fontSize={12}
                  fill={C.text}
                >
                  {truncate(n.slug, 18)}
                </text>
                {n.resource && (
                  <text
                    x={n.x + 10}
                    y={n.y + 34}
                    fontFamily={fonts.mono}
                    fontSize={10}
                    fill={
                      n.resource.backend_kind === "mint" ? C.blue : C.purple
                    }
                  >
                    {n.resource.backend_kind}
                  </text>
                )}
                {isGhost && (
                  <text
                    x={n.x + 10}
                    y={n.y + 34}
                    fontFamily={fonts.mono}
                    fontSize={10}
                    fill={C.danger}
                  >
                    missing
                  </text>
                )}
                {n.orphanTarget && (
                  <circle
                    cx={n.x + n.w - 8}
                    cy={n.y + 8}
                    r={4}
                    fill={C.danger}
                  >
                    <title>orphan target scope(s)</title>
                  </circle>
                )}
                {n.unusedSource && (
                  <circle
                    cx={n.x + n.w - 8}
                    cy={n.y + 20}
                    r={4}
                    fill={C.warn}
                  >
                    <title>unused source scope(s)</title>
                  </circle>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <div
        style={{
          display: "flex",
          gap: 16,
          marginTop: 12,
          fontSize: sz.sm,
          color: C.textDim,
          flexWrap: "wrap",
        }}
      >
        <span>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: C.danger,
              marginRight: 4,
            }}
          />
          orphan target scope
        </span>
        <span>
          <span
            style={{
              display: "inline-block",
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: C.warn,
              marginRight: 4,
            }}
          />
          unused source scope
        </span>
        <span>
          <span
            style={{
              display: "inline-block",
              width: 14,
              height: 2,
              background: C.textDim,
              marginRight: 4,
              verticalAlign: "middle",
            }}
          />
          drifted (scope-map references unknown scope)
        </span>
      </div>
    </div>
  );
}

interface Layout {
  width: number;
  height: number;
  nodes: NodeRect[];
  edges: {
    key: string;
    link: FrontingLinkView;
    path: string;
    midX: number;
    midY: number;
    drifted: boolean;
  }[];
}

function buildLayout(
  links: FrontingLinkView[],
  resources: ResourceView[],
): Layout {
  const byslug = new Map<string, ResourceView>();
  for (const r of resources) byslug.set(r.slug, r);

  const sourceSlugs = Array.from(
    new Set(links.map((l) => l.source_slug)),
  ).sort();
  const targetSlugs = Array.from(
    new Set(links.map((l) => l.target_slug)),
  ).sort();

  const nodes: NodeRect[] = [];
  const nodeBySide = new Map<string, NodeRect>(); // key = "left:slug" / "right:slug"

  sourceSlugs.forEach((slug, i) => {
    const r = byslug.get(slug) ?? null;
    const node: NodeRect = {
      slug,
      resource: r,
      side: "left",
      x: PAD_X,
      y: PAD_Y + i * (NODE_H + ROW_GAP),
      w: NODE_W,
      h: NODE_H,
      orphanTarget: false, // sources don't get orphan-target badge
      unusedSource: r ? hasUnusedSourceScope(r, slug, links) : false,
    };
    nodes.push(node);
    nodeBySide.set(`left:${slug}`, node);
  });

  targetSlugs.forEach((slug, i) => {
    const r = byslug.get(slug) ?? null;
    const node: NodeRect = {
      slug,
      resource: r,
      side: "right",
      x: PAD_X + NODE_W + COL_GAP,
      y: PAD_Y + i * (NODE_H + ROW_GAP),
      w: NODE_W,
      h: NODE_H,
      orphanTarget: r ? hasOrphanTargetScope(r, slug, links) : false,
      unusedSource: false, // targets don't get unused-source badge
    };
    nodes.push(node);
    nodeBySide.set(`right:${slug}`, node);
  });

  const width =
    PAD_X * 2 + NODE_W * 2 + COL_GAP;
  const height =
    PAD_Y * 2 +
    Math.max(sourceSlugs.length, targetSlugs.length) * (NODE_H + ROW_GAP);

  const edges = links.map((l) => {
    const a = nodeBySide.get(`left:${l.source_slug}`);
    const b = nodeBySide.get(`right:${l.target_slug}`);
    if (!a || !b) {
      // Both sides should always be present — defensive fall-through.
      return null;
    }
    const x1 = a.x + a.w;
    const y1 = a.y + a.h / 2;
    const x2 = b.x;
    const y2 = b.y + b.h / 2;
    const cpx = (x1 + x2) / 2;
    const path = `M ${x1} ${y1} C ${cpx} ${y1}, ${cpx} ${y2}, ${x2} ${y2}`;
    return {
      key: `${l.source_slug}/${l.target_slug}`,
      link: l,
      path,
      midX: (x1 + x2) / 2,
      midY: (y1 + y2) / 2,
      drifted: hasDrift(l, byslug),
    };
  });

  return {
    width,
    height,
    nodes,
    edges: edges.filter((e): e is NonNullable<typeof e> => e !== null),
  };
}

function hasDrift(
  l: FrontingLinkView,
  byslug: Map<string, ResourceView>,
): boolean {
  const src = byslug.get(l.source_slug);
  const tgt = byslug.get(l.target_slug);
  if (!src || !tgt) return true;
  const srcScopes = new Set(src.scopes.map((s) => s.name));
  const tgtScopes = new Set(tgt.scopes.map((s) => s.name));
  for (const k of Object.keys(l.scope_map)) {
    if (!srcScopes.has(k)) return true;
    for (const v of l.scope_map[k]) {
      if (!tgtScopes.has(v)) return true;
    }
  }
  return false;
}

function hasUnusedSourceScope(
  r: ResourceView,
  slug: string,
  links: FrontingLinkView[],
): boolean {
  if (r.backend_kind !== "mint") return false;
  const referenced = new Set<string>();
  for (const l of links) {
    if (l.source_slug !== slug) continue;
    for (const k of Object.keys(l.scope_map)) referenced.add(k);
  }
  for (const s of r.scopes) {
    if (!referenced.has(s.name)) return true;
  }
  return false;
}

function hasOrphanTargetScope(
  r: ResourceView,
  slug: string,
  links: FrontingLinkView[],
): boolean {
  const mapped = new Set<string>();
  for (const l of links) {
    if (l.target_slug !== slug) continue;
    for (const v of Object.values(l.scope_map).flat()) mapped.add(v);
  }
  for (const s of r.scopes) {
    if (!mapped.has(s.name)) return true;
  }
  return false;
}

function edgeLabel(l: FrontingLinkView, drifted: boolean): string {
  const k = Object.keys(l.scope_map).length;
  const v = new Set(Object.values(l.scope_map).flat()).size;
  const base = `${k}→${v}`;
  return drifted ? `${base} (drifted)` : base;
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

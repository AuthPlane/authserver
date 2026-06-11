// ResourceFrontingSection — embedded into the Resources drawer.
//
// "Fronts" section (Mint resources only): outbound links where this
// resource is the source.
// "Fronted by" section (always): inbound links where this resource is
// the target.
// Per-scope badge: count of links touching that scope as key (outbound)
// or value (inbound). Click → toggle inline list of {source}→{target}.
// Owns its own fetch (one /admin/resources/{slug}/fronting per mount).

import { useCallback, useEffect, useState } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { listFrontingForResource } from "../api";
import type {
  BackendKind,
  FrontingLinkView,
  ResourceFrontingView,
  ScopeView,
} from "../api";
import Btn from "./Btn";
import Mono from "./Mono";
import Tag from "./Tag";

interface ResourceFrontingSectionProps {
  slug: string;
  kind: BackendKind;
  scopes: ScopeView[];
  // Caller hooks for the action buttons; the section itself doesn't
  // open drawers — it asks the parent (Resources.tsx).
  onCreateLink: (preselectSourceSlug: string) => void;
  onEditLink: (link: FrontingLinkView) => void;
  // Optional render slot above the section (e.g. per-scope badges
  // rendered next to scope rows in the form). The component computes
  // counts and exposes them via this callback.
  onScopeCountsChange?: (counts: ScopePerLinkCounts) => void;
}

export interface ScopePerLinkCounts {
  // For each scope name, the list of links touching it.
  [scopeName: string]: FrontingLinkView[];
}

export default function ResourceFrontingSection({
  slug,
  kind,
  scopes,
  onCreateLink,
  onEditLink,
  onScopeCountsChange,
}: ResourceFrontingSectionProps) {
  const [data, setData] = useState<ResourceFrontingView | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const d = await listFrontingForResource(slug);
      setData(d);
      setError("");
      if (onScopeCountsChange) {
        onScopeCountsChange(computeScopeCounts(scopes, d));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fronting");
    }
  }, [slug, scopes, onScopeCountsChange]);

  useEffect(() => {
    load();
  }, [load]);

  if (error) {
    return (
      <div
        style={{
          padding: "8px 12px",
          background: alpha(C.danger, 0x12),
          border: `1px solid ${alpha(C.danger, 0x40)}`,
          borderRadius: 6,
          fontSize: sz.sm,
          color: C.danger,
        }}
      >
        {error}
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{ fontSize: sz.sm, color: C.textDim, fontStyle: "italic" }}>
        Loading fronting links…
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {kind === "mint" && (
        <FrontingList
          title="Fronts"
          subtitle="Outbound links — this resource is the source."
          emptyText="This Resource doesn't front any other Resource."
          links={data.fronts}
          slug={slug}
          showCreate
          onCreate={() => onCreateLink(slug)}
          onEdit={onEditLink}
        />
      )}
      <FrontingList
        title="Fronted by"
        subtitle="Inbound links — this resource is the target."
        emptyText="This Resource isn't fronted by any other Resource."
        links={data.fronted_by}
        slug={slug}
        showCreate={false}
        onCreate={() => onCreateLink(slug)}
        onEdit={onEditLink}
      />
    </div>
  );
}

interface FrontingListProps {
  title: string;
  subtitle: string;
  emptyText: string;
  links: FrontingLinkView[];
  slug: string;
  showCreate: boolean;
  onCreate: () => void;
  onEdit: (l: FrontingLinkView) => void;
}

function FrontingList({
  title,
  subtitle,
  emptyText,
  links,
  showCreate,
  onCreate,
  onEdit,
}: FrontingListProps) {
  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          marginBottom: 4,
          gap: 12,
        }}
      >
        <div
          style={{
            fontFamily: fonts.mono,
            fontSize: sz.sm,
            fontWeight: 500,
            color: C.text,
            textTransform: "uppercase",
            letterSpacing: 1,
          }}
        >
          {title}
          {links.length > 0 && (
            <span
              style={{
                marginLeft: 8,
                color: C.textDim,
                fontWeight: 400,
              }}
            >
              ({links.length})
            </span>
          )}
        </div>
        {showCreate && (
          <Btn small secondary onClick={onCreate}>
            + Add fronting link
          </Btn>
        )}
      </div>
      <div
        style={{ fontSize: sz.sm, color: C.textDim, marginBottom: 8 }}
      >
        {subtitle}
      </div>
      {links.length === 0 ? (
        <div
          style={{
            padding: "10px 12px",
            background: C.surface2,
            border: `1px dashed ${C.border2}`,
            borderRadius: 6,
            fontSize: sz.sm,
            color: C.textDim,
          }}
        >
          {emptyText}
        </div>
      ) : (
        <div style={{ display: "grid", gap: 6 }}>
          {links.map((l) => {
            const summary = `${Object.keys(l.scope_map).length}→${
              new Set(Object.values(l.scope_map).flat()).size
            }`;
            return (
              <div
                key={`${l.source_slug}/${l.target_slug}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "6px 10px",
                  background: C.surface2,
                  border: `1px solid ${C.border2}`,
                  borderRadius: 6,
                }}
              >
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <Mono>{l.source_slug}</Mono>
                  <span style={{ color: C.textDim }}>→</span>
                  <Mono>{l.target_slug}</Mono>
                  <Tag color={C.textDim}>{summary}</Tag>
                </div>
                <Btn small secondary onClick={() => onEdit(l)}>
                  Edit
                </Btn>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function computeScopeCounts(
  scopes: ScopeView[],
  data: ResourceFrontingView,
): ScopePerLinkCounts {
  const out: ScopePerLinkCounts = {};
  for (const s of scopes) {
    const touching: FrontingLinkView[] = [];
    for (const l of data.fronts) {
      if (Object.keys(l.scope_map).includes(s.name)) touching.push(l);
    }
    for (const l of [...data.fronts, ...data.fronted_by]) {
      if (Object.values(l.scope_map).flat().includes(s.name)) {
        if (!touching.includes(l)) touching.push(l);
      }
    }
    if (touching.length > 0) out[s.name] = touching;
  }
  return out;
}

// Companion component for inline rendering of per-scope counts.
// Use this from inside Resources.tsx next to each scope row in the form.
interface ScopeBadgeProps {
  scopeName: string;
  links: FrontingLinkView[];
}

export function ScopeFrontingBadge({ scopeName, links }: ScopeBadgeProps) {
  const [open, setOpen] = useState(false);
  if (links.length === 0) return null;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <span
        onClick={() => setOpen((o) => !o)}
        style={{
          background: alpha(C.accent, 0x10),
          border: `1px solid ${alpha(C.accent, 0x30)}`,
          color: C.accent,
          borderRadius: 3,
          padding: "1px 6px",
          fontFamily: fonts.mono,
          fontSize: sz.xs,
          cursor: "pointer",
          width: "fit-content",
        }}
        title={`${links.length} fronting link(s) reference '${scopeName}'`}
      >
        {links.length} link{links.length === 1 ? "" : "s"}
      </span>
      {open && (
        <div
          style={{
            background: C.surface2,
            border: `1px solid ${C.border2}`,
            borderRadius: 4,
            padding: "4px 8px",
            fontFamily: fonts.mono,
            fontSize: sz.xs,
            color: C.textDim,
          }}
        >
          {links.map((l) => (
            <div key={`${l.source_slug}/${l.target_slug}`}>
              {l.source_slug} → {l.target_slug}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

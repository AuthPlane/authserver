// Fronting.tsx — admin surface for cross-Mint fronting links.
//
// Two tabs: List (table of all links) and Graph (DAG view, Task 7).
// Source picker constrained to Mint Resources; target picker accepts both
// kinds. The Resources Drawer integration (per-scope badges, Fronts/Fronted
// by sections) lives in Resources.tsx via ResourceFrontingSection.

import { useCallback, useEffect, useMemo, useState } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { listFrontingLinks, listResources } from "../api";
import type { FrontingLinkView, ResourceView } from "../api";
import Btn from "../components/Btn";
import Card from "../components/Card";
import Mono from "../components/Mono";
import Tag from "../components/Tag";
import TextInput from "../components/TextInput";
import Toast from "../components/Toast";
import FrontingLinkDrawer from "../components/FrontingLinkDrawer";
import FrontingGraph from "../components/FrontingGraph";

type Tab = "list" | "graph";
type Editing = FrontingLinkView | "new" | null;
type KindFilter = "all" | "mint-mint" | "mint-broker";

export default function Fronting() {
  const [links, setLinks] = useState<FrontingLinkView[]>([]);
  const [resources, setResources] = useState<ResourceView[]>([]);
  const [tab, setTab] = useState<Tab>("list");
  const [filterSource, setFilterSource] = useState("");
  const [filterTarget, setFilterTarget] = useState("");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [editing, setEditing] = useState<Editing>(null);
  const [initialCreateSource, setInitialCreateSource] = useState("");
  const [error, setError] = useState("");
  const [toast, setToast] = useState<{
    msg: string;
    type: "success" | "error";
  } | null>(null);

  const showToast = (msg: string, type: "success" | "error" = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async () => {
    try {
      const [ls, rs] = await Promise.all([
        listFrontingLinks(),
        listResources(),
      ]);
      setLinks(ls);
      setResources(rs);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Honor hash-query hints so other pages can deep-link into the drawer.
  // - #/fronting?new=1[&source=slug]   → open create drawer (preselected)
  // - #/fronting?openLink=src/tgt      → open edit drawer for that link
  useEffect(() => {
    const hash = window.location.hash;
    const qIdx = hash.indexOf("?");
    if (qIdx === -1) return;
    const params = new URLSearchParams(hash.slice(qIdx + 1));
    if (params.get("new") === "1") {
      setEditing("new");
      setInitialCreateSource(params.get("source") ?? "");
      // Strip params so reloads don't re-open.
      window.history.replaceState(null, "", hash.slice(0, qIdx));
      return;
    }
    const open = params.get("openLink");
    if (open && links.length > 0) {
      const [src, tgt] = open.split("/");
      const found = links.find(
        (l) => l.source_slug === src && l.target_slug === tgt,
      );
      // Always strip the params once we have data to act on, even if the
      // link is gone — bookmarks pointing at a deleted link otherwise leak
      // params on every reload.
      window.history.replaceState(null, "", hash.slice(0, qIdx));
      if (found) {
        setEditing(found);
      } else {
        showToast(`Fronting link ${src} → ${tgt} not found`, "error");
      }
    }
  }, [links]);

  // Slug → backend_kind, used by the kind filter to decide whether a link's
  // target is a Mint or Broker. Memoized so the filter pass below stays O(N)
  // even as the filter UI re-renders.
  const kindBySlug = useMemo(() => {
    const m = new Map<string, "mint" | "broker">();
    for (const r of resources) m.set(r.slug, r.backend_kind);
    return m;
  }, [resources]);

  const filterSrcLower = filterSource.toLowerCase();
  const filterTgtLower = filterTarget.toLowerCase();
  const filtered = links.filter((l) => {
    if (filterSrcLower && !l.source_slug.toLowerCase().includes(filterSrcLower)) return false;
    if (filterTgtLower && !l.target_slug.toLowerCase().includes(filterTgtLower)) return false;
    if (kindFilter !== "all") {
      const tk = kindBySlug.get(l.target_slug);
      if (kindFilter === "mint-mint" && tk !== "mint") return false;
      if (kindFilter === "mint-broker" && tk !== "broker") return false;
    }
    return true;
  });

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
        <div
          style={{
            fontFamily: fonts.mono,
            fontSize: sz.xl,
            fontWeight: 600,
          }}
        >
          Fronting
        </div>
        <div
          style={{ fontSize: sz.base, color: C.textDim, marginTop: 2 }}
        >
          Cross-Mint fronting links — operator-declared bridges that let one
          Mint resource exchange tokens for another via RFC 8693.
        </div>
      </div>

      {error && (
        <div
          style={{
            marginBottom: 14,
            padding: "8px 14px",
            background: alpha(C.danger, 0x12),
            border: `1px solid ${alpha(C.danger, 0x40)}`,
            borderRadius: 6,
            fontSize: sz.base,
            color: C.danger,
          }}
        >
          {error}
        </div>
      )}

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 14,
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", gap: 4 }}>
          {(["list", "graph"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                padding: "5px 14px",
                borderRadius: 5,
                border: `1px solid ${tab === t ? alpha(C.accent, 0x50) : C.border2}`,
                background: tab === t ? alpha(C.accent, 0x18) : "transparent",
                color: tab === t ? C.accent : C.textDim,
                cursor: "pointer",
                fontFamily: fonts.mono,
                fontSize: sz.sm,
                transition: "all 0.15s",
              }}
            >
              {t}
            </button>
          ))}
        </div>
        <Btn onClick={() => setEditing("new")}>+ New Fronting Link</Btn>
      </div>

      {tab === "list" && (
        <>
          <div
            style={{
              display: "flex",
              gap: 10,
              marginBottom: 14,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <div style={{ width: 220 }}>
              <TextInput
                placeholder="Filter source slug…"
                value={filterSource}
                onChange={setFilterSource}
              />
            </div>
            <div style={{ width: 220 }}>
              <TextInput
                placeholder="Filter target slug…"
                value={filterTarget}
                onChange={setFilterTarget}
              />
            </div>
            {/* Kind filter: scopes the table to Mint→Mint or Mint→Broker
                rows. Useful in mixed deployments where a search by slug
                alone returns both kinds and the operator only cares about
                one side (e.g. auditing broker exchanges). */}
            <div style={{ display: "flex", gap: 4 }}>
              {(
                [
                  ["all", "all"],
                  ["mint-mint", "Mint→Mint"],
                  ["mint-broker", "Mint→Broker"],
                ] as [KindFilter, string][]
              ).map(([opt, label]) => (
                <button
                  key={opt}
                  onClick={() => setKindFilter(opt)}
                  style={{
                    padding: "5px 12px",
                    borderRadius: 5,
                    border: `1px solid ${kindFilter === opt ? alpha(C.accent, 0x50) : C.border2}`,
                    background: kindFilter === opt ? alpha(C.accent, 0x18) : "transparent",
                    color: kindFilter === opt ? C.accent : C.textDim,
                    cursor: "pointer",
                    fontFamily: fonts.mono,
                    fontSize: sz.sm,
                    transition: "all 0.15s",
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {links.length === 100 && (
            <div
              style={{
                marginBottom: 14,
                padding: "6px 12px",
                background: alpha(C.warn, 0x12),
                border: `1px solid ${alpha(C.warn, 0x40)}`,
                borderRadius: 6,
                fontSize: sz.sm,
                color: C.warn,
              }}
            >
              Showing first 100 links. Use filters to narrow.
            </div>
          )}

          <Card style={{ padding: 0 }}>
            <table
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: sz.base,
              }}
            >
              <thead>
                <tr>
                  {["Source", "Target", "Scope map", "Created", "Created by"].map(
                    (h) => (
                      <th
                        key={h}
                        style={{
                          textAlign: "left",
                          padding: "8px 12px",
                          color: C.textDim,
                          fontFamily: fonts.mono,
                          fontSize: sz.xs,
                          textTransform: "uppercase",
                          letterSpacing: 1.2,
                          borderBottom: `1px solid ${C.border}`,
                          fontWeight: 400,
                        }}
                      >
                        {h}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {filtered.map((l) => {
                  const summary = scopeMapSummary(l.scope_map);
                  return (
                    <tr
                      key={`${l.source_slug}/${l.target_slug}`}
                      onClick={() => setEditing(l)}
                      style={{
                        cursor: "pointer",
                        borderBottom: `1px solid ${C.border}`,
                        transition: "background 0.1s",
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.background = C.surface2;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.background = "transparent";
                      }}
                    >
                      <td style={{ padding: "10px 12px" }}>
                        <Mono>{l.source_slug}</Mono>
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <Mono>{l.target_slug}</Mono>
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <span style={{ fontSize: sz.sm, color: C.textDim }}>
                          {summary}
                        </span>
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <span style={{ fontSize: sz.sm, color: C.textDim }}>
                          {l.created_at}
                        </span>
                      </td>
                      <td style={{ padding: "10px 12px" }}>
                        <Tag color={C.textDim}>{l.created_by}</Tag>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div
                style={{
                  padding: "20px 12px",
                  fontSize: sz.base,
                  color: C.textDim,
                  textAlign: "center",
                }}
              >
                {links.length === 0
                  ? "No fronting links yet. Create one to bridge two Mint resources."
                  : "No links match your filters."}
              </div>
            )}
          </Card>
        </>
      )}

      {tab === "graph" && (
        <Card>
          <FrontingGraph
            links={links}
            resources={resources}
            onNodeClick={(slug) => {
              window.location.hash = `#/resources?highlight=${encodeURIComponent(slug)}`;
            }}
            onEdgeClick={(l) => setEditing(l)}
          />
        </Card>
      )}

      {editing && (
        <FrontingLinkDrawer
          key={
            editing === "new"
              ? "__new__"
              : `${editing.source_slug}/${editing.target_slug}`
          }
          mode={editing === "new" ? "create" : "edit"}
          link={editing === "new" ? undefined : editing}
          resources={resources}
          initialSource={editing === "new" ? initialCreateSource : undefined}
          onClose={() => {
            setEditing(null);
            setInitialCreateSource("");
          }}
          onSaved={() => {
            const wasCreate = editing === "new";
            setEditing(null);
            setInitialCreateSource("");
            showToast(wasCreate ? "Fronting link created" : "Saved");
            load();
          }}
        />
      )}

      <Toast message={toast?.msg ?? null} type={toast?.type} />
    </div>
  );
}

// Compact summary for the table column: e.g. "2 keys → 3 values".
function scopeMapSummary(m: Record<string, string[]>): string {
  const keys = Object.keys(m).length;
  const values = new Set(Object.values(m).flat()).size;
  if (keys === 0) return "(empty)";
  return `${keys} key${keys === 1 ? "" : "s"} → ${values} value${values === 1 ? "" : "s"}`;
}

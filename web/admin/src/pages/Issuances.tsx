// Issuances.tsx — admin surface for /admin/issuances (the design, ).
//
// Forensic surface: every token Authplane has minted (Mint) or vended
// (Broker) is recorded here. The list endpoint accepts any combination of
// ?user, ?client, ?resource, ?jti (at least one required); supplying more
// than one narrows the result. The UI offers a dropdown per dimension so
// operators can build the same composed filter that Grants → Issuances
// cross-links pre-populate via URL hash params.
//
// "Since" still falls away when JTI is supplied — matches the API's
// "?since= ignored for jti lookups" semantic.

import { useState, useCallback, useEffect } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import {
  listUsers, listClients, listResources,
  listIssuances, lookupIssuanceByJTI, revokeIssuance,
} from "../api";
import type {
  UserView, ClientView, ResourceView, IssuanceView, IssuanceListResponse,
  BackendKind,
} from "../api";
import Btn from "../components/Btn";
import Card from "../components/Card";
import Mono from "../components/Mono";
import Tag from "../components/Tag";
import TextInput from "../components/TextInput";
import Drawer from "../components/Drawer";
import DrawerRow from "../components/DrawerRow";
import Modal from "../components/Modal";
import Toast from "../components/Toast";
import SectionTitle from "../components/SectionTitle";
import AgentChain from "../components/AgentChain";
import JsonView from "../components/JsonView";

// readHashQuery parses ?key=value pairs from the current HashRouter URL
// (e.g. "#/issuances?user=alice&resource=github"). Returned object is
// keyed by lowercase param name. Cross-link entry points from Grants and
// Users pages depend on this — keep names stable.
function readHashQuery(): Record<string, string> {
  const hash = window.location.hash;
  const q = hash.indexOf("?");
  if (q < 0) return {};
  const params = new URLSearchParams(hash.slice(q + 1));
  const out: Record<string, string> = {};
  params.forEach((v, k) => { out[k.toLowerCase()] = v; });
  return out;
}

interface SinceOption {
  label: string;
  hours: number;
}

const SINCE_OPTIONS: SinceOption[] = [
  { label: "Last 24h", hours: 24 },
  { label: "Last 7d", hours: 24 * 7 },
  { label: "Last 30d", hours: 24 * 30 },
];

function truncate(s: string, n = 12): string {
  return s.length > n ? s.substring(0, n) + "…" : s;
}

function formatDateTime(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function backendColor(k: BackendKind): string {
  return k === "mint" ? C.blue : C.purple;
}

const selectStyle: React.CSSProperties = {
  width: "100%",
  background: C.surface2,
  border: `1px solid ${C.border2}`,
  borderRadius: 5,
  padding: "6px 10px",
  color: C.text,
  fontSize: sz.base,
  fontFamily: fonts.mono,
};

function FilterColumn({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: sz.xs, color: C.textDim, fontFamily: fonts.mono, textTransform: "uppercase", letterSpacing: 1.2, marginBottom: 4 }}>{label}</div>
      {children}
    </div>
  );
}

// CrossLinkValue renders a Mono label that doubles as a click-target to
// another admin page.
// Uses href= so middle-click / cmd-click open the cross-link in a new tab.
function CrossLinkValue({ label, href, title }: { label: string; href: string; title: string }) {
  return (
    <a
      href={href}
      title={title}
      style={{
        color: C.accent,
        textDecoration: "none",
        borderBottom: `1px dashed ${alpha(C.accent, 0x60)}`,
        fontFamily: fonts.mono,
        fontSize: sz.sm,
      }}
    >
      {label}
    </a>
  );
}

function statusOf(i: IssuanceView): "active" | "revoked" | "expired" {
  if (i.revoked_at) return "revoked";
  if (i.expires_at && new Date(i.expires_at).getTime() < Date.now()) return "expired";
  return "active";
}

function statusColor(s: "active" | "revoked" | "expired"): string {
  if (s === "active") return C.success;
  if (s === "revoked") return C.danger;
  return C.textDim;
}

export default function Issuances() {
  const [users, setUsers] = useState<UserView[]>([]);
  const [clients, setClients] = useState<ClientView[]>([]);
  const [resources, setResources] = useState<ResourceView[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);

  // filters are now composable instead of mutually exclusive.
  // The Search button requires at least one of {user, client, resource,
  // jti} non-empty (matches the server's 400 contract).
  const [userValue, setUserValue] = useState("");
  const [clientValue, setClientValue] = useState("");
  const [resourceValue, setResourceValue] = useState("");
  const [jtiValue, setJtiValue] = useState("");
  const [sinceHours, setSinceHours] = useState<number>(24);

  const [response, setResponse] = useState<IssuanceListResponse | null>(null);
  const [searching, setSearching] = useState(false);

  const [selected, setSelected] = useState<IssuanceView | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [confirmingRevoke, setConfirmingRevoke] = useState<IssuanceView | null>(null);

  const showToast = (msg: string, type: "success" | "error" = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const loadDirectory = useCallback(async () => {
    try {
      const [us, cs, rs] = await Promise.all([listUsers(), listClients(), listResources()]);
      setUsers(us);
      setClients(cs);
      setResources(rs);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load directory");
    }
  }, []);

  useEffect(() => { loadDirectory(); }, [loadDirectory]);

  // Cross-link entry: read filters from the URL hash query (e.g. when the
  // operator clicks "View issuances" on a consent grant). Run after the
  // directory load so the selects render with the matching options
  // already populated. The auto-search keeps the cross-link feeling
  // direct — operator goes straight from grant → matching rows.
  const sinceISO = useCallback((): string | undefined => {
    const t = new Date(Date.now() - sinceHours * 3600 * 1000);
    return t.toISOString();
  }, [sinceHours]);

  const runSearch = useCallback(async (filters: { user?: string; client?: string; resource?: string; jti?: string }) => {
    setSearching(true);
    setResponse(null);
    try {
      let res: IssuanceListResponse;
      if (filters.jti) {
        // JTI is still a point-query; ?since= is ignored. Other filters
        // narrow the single-row result.
        res = await lookupIssuanceByJTI(filters.jti.trim(), {
          user: filters.user || undefined,
          client: filters.client || undefined,
          resource: filters.resource || undefined,
        });
      } else {
        res = await listIssuances({
          user: filters.user || undefined,
          client: filters.client || undefined,
          resource: filters.resource || undefined,
          since: sinceISO(),
          limit: 500,
        });
      }
      setResponse(res);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Search failed", "error");
    } finally {
      setSearching(false);
    }
  }, [sinceISO]);

  // applyHashCrossLink reads ?user=/?client=/?resource=/?jti= from the
  // current hash, pushes them into the filter state, kicks off a search,
  // and clears the params from the URL so a subsequent manual Search
  // doesn't keep re-running them. No-op when no params are present.
  const applyHashCrossLink = useCallback(() => {
    const q = readHashQuery();
    if (!q.user && !q.client && !q.resource && !q.jti) return;
    const u = q.user || "";
    const c = q.client || "";
    const r = q.resource || "";
    const j = q.jti || "";
    setUserValue(u);
    setClientValue(c);
    setResourceValue(r);
    setJtiValue(j);
    runSearch({ user: u, client: c, resource: r, jti: j });
    const hash = window.location.hash;
    const sep = hash.indexOf("?");
    if (sep >= 0) {
      window.history.replaceState(null, "", hash.slice(0, sep));
    }
  }, [runSearch]);

  // First-load cross-link handling — runs once after the directory list
  // populates so the selects can render the picked option immediately.
  useEffect(() => {
    if (users.length === 0 && clients.length === 0 && resources.length === 0) return;
    applyHashCrossLink();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [users.length, clients.length, resources.length]);

  // In-page navigation: a CrossLinkValue link inside the Drawer changes
  // the URL hash without unmounting the page. Listen for `hashchange`
  // so those clicks still pivot the filter state.
  useEffect(() => {
    const onHashChange = () => { applyHashCrossLink(); };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [applyHashCrossLink]);

  const activeFilterCount = (
    (userValue ? 1 : 0) +
    (clientValue ? 1 : 0) +
    (resourceValue ? 1 : 0) +
    (jtiValue.trim() ? 1 : 0)
  );

  const clearFilters = () => {
    setUserValue("");
    setClientValue("");
    setResourceValue("");
    setJtiValue("");
    setResponse(null);
  };

  const search = async () => {
    if (activeFilterCount === 0) {
      showToast("Pick at least one filter (user, client, resource, or JTI)", "error");
      return;
    }
    await runSearch({ user: userValue, client: clientValue, resource: resourceValue, jti: jtiValue.trim() });
  };

  const performRevoke = async (i: IssuanceView) => {
    setRevoking(true);
    try {
      await revokeIssuance(i.id);
      showToast("Issuance revoked");
      setConfirmingRevoke(null);
      setSelected(null);
      // Re-run the current search so the row updates inline.
      if (activeFilterCount > 0) {
        runSearch({ user: userValue, client: clientValue, resource: resourceValue, jti: jtiValue.trim() });
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to revoke", "error");
    } finally {
      setRevoking(false);
    }
  };

  const userLabel = (id: string): string => {
    const u = users.find((uu) => uu.id === id);
    return u ? (u.email || u.name || id) : id;
  };
  const clientLabel = (id: string): string => {
    const c = clients.find((cc) => cc.id === id);
    return c ? c.name : id;
  };
  const resourceLabel = (id: string): string => {
    const r = resources.find((rr) => rr.id === id);
    return r ? r.slug : id;
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: fonts.mono, fontSize: sz.xl, fontWeight: 600 }}>Issuances</div>
        <div style={{ fontSize: sz.base, color: C.textDim, marginTop: 2 }}>
          Forensic record of every token Authplane has minted or brokered. Combine user / client / resource / JTI filters to narrow the result.
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 14, padding: "8px 14px", background: alpha(C.danger, 0x12), border: `1px solid ${alpha(C.danger, 0x40)}`, borderRadius: 6, fontSize: sz.base, color: C.danger }}>
          {error}
        </div>
      )}

      <Card style={{ marginBottom: 18 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(180px, 1fr))", gap: 10, marginBottom: 12 }}>
          <FilterColumn label="User">
            <select
              value={userValue}
              onChange={(e) => setUserValue(e.target.value)}
              style={selectStyle}
            >
              <option value="">— any —</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.email || u.name || u.id}</option>
              ))}
            </select>
          </FilterColumn>
          <FilterColumn label="Client">
            <select
              value={clientValue}
              onChange={(e) => setClientValue(e.target.value)}
              style={selectStyle}
            >
              <option value="">— any —</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name} ({truncate(c.id, 8)})</option>
              ))}
            </select>
          </FilterColumn>
          <FilterColumn label="Resource">
            <select
              value={resourceValue}
              onChange={(e) => setResourceValue(e.target.value)}
              style={selectStyle}
            >
              <option value="">— any —</option>
              {resources.map((r) => (
                <option key={r.id} value={r.id}>{r.slug}</option>
              ))}
            </select>
          </FilterColumn>
          <FilterColumn label="JTI">
            <TextInput placeholder="Paste a JTI…" value={jtiValue} onChange={setJtiValue} />
          </FilterColumn>
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          {jtiValue.trim() === "" && (
            <div style={{ display: "flex", gap: 4 }}>
              {SINCE_OPTIONS.map((opt) => (
                <button
                  key={opt.hours}
                  onClick={() => setSinceHours(opt.hours)}
                  style={{
                    padding: "6px 12px",
                    borderRadius: 5,
                    border: `1px solid ${sinceHours === opt.hours ? alpha(C.accent, 0x50) : C.border2}`,
                    background: sinceHours === opt.hours ? alpha(C.accent, 0x18) : "transparent",
                    color: sinceHours === opt.hours ? C.accent : C.textDim,
                    cursor: "pointer",
                    fontFamily: fonts.mono,
                    fontSize: sz.sm,
                  }}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
          {jtiValue.trim() !== "" && (
            <span style={{ fontSize: sz.sm, color: C.textDim, fontStyle: "italic" }}>
              since window ignored for JTI lookups
            </span>
          )}
          <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
            {activeFilterCount > 0 && (
              <Btn secondary onClick={clearFilters} disabled={searching}>Clear</Btn>
            )}
            <Btn onClick={search} disabled={searching}>
              {searching ? "Searching…" : `Search${activeFilterCount > 1 ? ` (${activeFilterCount} filters)` : ""}`}
            </Btn>
          </div>
        </div>
      </Card>

      {response && (
        <Card style={{ padding: 0 }}>
          <div style={{ padding: "10px 14px", borderBottom: `1px solid ${C.border}`, fontSize: sz.sm, color: C.textDim, display: "flex", justifyContent: "space-between" }}>
            <span>{response.count} issuance{response.count === 1 ? "" : "s"}</span>
            {jtiValue.trim() === "" && response.since && new Date(response.since).getTime() > 0 && (
              <span>since {formatDateTime(response.since)}</span>
            )}
          </div>
          {response.issuances.length === 0 ? (
            <div style={{ padding: "20px 14px", fontSize: sz.base, color: C.textDim, textAlign: "center" }}>
              {jtiValue.trim() !== "" ? "No issuance with that JTI." : "No issuances match the current filters."}
            </div>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: sz.base }}>
              <thead>
                <tr>
                  {["JTI", "User", "Client", "Resource", "Backend", "Issued", "Status", ""].map((h) => (
                    <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: C.textDim, fontFamily: fonts.mono, fontSize: sz.xs, textTransform: "uppercase", letterSpacing: 1.2, borderBottom: `1px solid ${C.border}`, fontWeight: 400 }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {response.issuances.map((i) => {
                  const s = statusOf(i);
                  return (
                    <tr
                      key={i.id}
                      onClick={() => setSelected(i)}
                      style={{ cursor: "pointer", borderBottom: `1px solid ${C.border}`, transition: "background 0.1s" }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = C.surface2; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                    >
                      <td style={{ padding: "8px 12px" }}>
                        <Mono style={{ fontSize: sz.sm }}>{i.jti ? truncate(i.jti, 14) : "—"}</Mono>
                      </td>
                      <td style={{ padding: "8px 12px" }}>
                        <Mono style={{ fontSize: sz.sm }}>{userLabel(i.subject_user_id)}</Mono>
                      </td>
                      <td style={{ padding: "8px 12px" }}>
                        <Mono style={{ fontSize: sz.sm }}>{clientLabel(i.client_id)}</Mono>
                      </td>
                      <td style={{ padding: "8px 12px" }}>
                        <Mono style={{ fontSize: sz.sm }}>{resourceLabel(i.resource_id)}</Mono>
                      </td>
                      <td style={{ padding: "8px 12px" }}>
                        <Tag color={backendColor(i.backend_kind)}>{i.backend_kind}</Tag>
                      </td>
                      <td style={{ padding: "8px 12px", color: C.textDim, fontSize: sz.sm }}>
                        {formatDateTime(i.issued_at)}
                      </td>
                      <td style={{ padding: "8px 12px" }}>
                        <Tag color={statusColor(s)}>{s}</Tag>
                      </td>
                      <td style={{ padding: "8px 12px", textAlign: "right" }}>
                        {s === "active" && i.revocable && (
                          <div onClick={(e) => e.stopPropagation()}>
                            <Btn danger small onClick={() => setConfirmingRevoke(i)}>Revoke</Btn>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {selected && (
        <Drawer
          title="Issuance Detail"
          subtitle={selected.jti ? truncate(selected.jti, 22) : truncate(selected.id, 22)}
          onClose={() => setSelected(null)}
          width={520}
        >
          <DrawerRow label="id" value={<Mono style={{ fontSize: sz.sm }}>{selected.id}</Mono>} />
          <DrawerRow label="jti" value={
            selected.jti
              ? <Mono style={{ fontSize: sz.sm }}>{selected.jti}</Mono>
              : <span style={{ color: C.textDim, fontStyle: "italic" }}>(broker — no JTI)</span>
          } />
          <DrawerRow label="subject_user" value={
            <CrossLinkValue
              label={userLabel(selected.subject_user_id)}
              href={`#/issuances?user=${encodeURIComponent(selected.subject_user_id)}`}
              title="Filter issuances by this user"
            />
          } />
          <DrawerRow label="client" value={
            <CrossLinkValue
              label={clientLabel(selected.client_id)}
              href={`#/issuances?client=${encodeURIComponent(selected.client_id)}`}
              title="Filter issuances by this client"
            />
          } />
          <DrawerRow label="resource" value={
            <CrossLinkValue
              label={resourceLabel(selected.resource_id)}
              href={`#/issuances?resource=${encodeURIComponent(selected.resource_id)}`}
              title="Filter issuances by this resource"
            />
          } />
          <DrawerRow label="backend" value={<Tag color={backendColor(selected.backend_kind)}>{selected.backend_kind}</Tag>} />
          <DrawerRow label="scopes" value={
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {selected.scopes.length === 0
                ? <span style={{ color: C.textDim }}>—</span>
                : selected.scopes.map((s) => <Tag key={s} color={C.blue}>{s}</Tag>)}
            </div>
          } />
          <DrawerRow label="revocable" value={selected.revocable ? "yes" : "no"} />
          <DrawerRow label="issued_at" value={formatDateTime(selected.issued_at)} />
          <DrawerRow label="expires_at" value={formatDateTime(selected.expires_at)} />
          <DrawerRow label="revoked_at" value={selected.revoked_at ? formatDateTime(selected.revoked_at) : "—"} />
          <DrawerRow label="dpop_jkt" value={
            selected.dpop_jkt
              ? <Mono style={{ fontSize: sz.sm }}>{truncate(selected.dpop_jkt, 24)}</Mono>
              : <span style={{ color: C.textDim }}>—</span>
          } />
          <DrawerRow label="agent_id" value={
            selected.agent_id
              ? <Mono style={{ fontSize: sz.sm }}>{selected.agent_id}</Mono>
              : <span style={{ color: C.textDim }}>—</span>
          } />

          {selected.agent_chain.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <SectionTitle>Agent Chain</SectionTitle>
              <AgentChain chain={selected.agent_chain} />
            </div>
          )}

          {/*
            Cross-link affordances are the dashed-underline links on the
            subject_user / client / resource rows above — clicking them
            re-filters the Issuances list itself. Links to Users / Grants /
            Audit pages are deliberately NOT added here yet: those pages
            do not read URL query params today (AuditLog has no client_id
            filter at all), so a "navigate with filter pre-applied"
            promise would land the operator on an unfiltered page. That
            wiring is tracked separately.
          */}

          <div style={{ marginTop: 18 }}>
            <SectionTitle>Raw record</SectionTitle>
            <JsonView value={selected} />
          </div>

          {statusOf(selected) === "active" && selected.revocable && (
            <div style={{ marginTop: 18, paddingTop: 14, borderTop: `1px solid ${C.border}` }}>
              <Btn danger full onClick={() => setConfirmingRevoke(selected)}>Revoke Issuance</Btn>
            </div>
          )}
        </Drawer>
      )}

      {confirmingRevoke && (
        <Modal
          title="Revoke issuance?"
          titleColor={C.danger}
          onClose={() => setConfirmingRevoke(null)}
        >
          <div style={{ fontSize: sz.base, color: C.textDim, lineHeight: 1.7, marginBottom: 16 }}>
            Revoke this issuance (jti=<Mono>{confirmingRevoke.jti ? truncate(confirmingRevoke.jti, 18) : "—"}</Mono>)?
            {" "}Mint tokens become inactive at next introspection; Broker tokens keep working at the upstream until they expire.
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <Btn secondary small onClick={() => setConfirmingRevoke(null)}>Cancel</Btn>
            <Btn danger small disabled={revoking} onClick={() => performRevoke(confirmingRevoke)}>
              {revoking ? "Revoking…" : "Revoke"}
            </Btn>
          </div>
        </Modal>
      )}

      <Toast message={toast?.msg ?? null} type={toast?.type} />
    </div>
  );
}

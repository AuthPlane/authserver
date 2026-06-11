import { useState, useEffect, useCallback } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { listClients, suspendClient, revokeClient, reactivateClient, createClient, rotateClientSecret, updateClient } from "../api";
import type { ClientView, CreateClientResponse, RotateSecretResponse, UpdateClientRequest } from "../api";
import Card from "../components/Card";
import Btn from "../components/Btn";
import Tag from "../components/Tag";
import Mono from "../components/Mono";
import StatusDot from "../components/StatusDot";
import TextInput from "../components/TextInput";
import Drawer from "../components/Drawer";
import DrawerRow from "../components/DrawerRow";
import SectionTitle from "../components/SectionTitle";
import Toast from "../components/Toast";
import Modal from "../components/Modal";
import Label from "../components/Label";
import Toggle from "../components/Toggle";

function truncate(id: string): string {
  return id.length > 8 ? id.substring(0, 8) + "…" : id;
}

function clientType(c: ClientView): string {
  if (c.registration_source === "agent") return "agent";
  if (c.token_endpoint_auth_method === "none") return "public";
  return "confidential";
}

function typeColor(t: string): string {
  if (t === "agent") return C.purple;
  if (t === "confidential") return C.blue;
  return C.textDim;
}

function formatDate(iso: string): string {
  if (!iso) return "\u2014";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

const GRANT_TYPE_OPTIONS = [
  { value: "authorization_code", label: "authorization_code" },
  { value: "client_credentials", label: "client_credentials" },
  { value: "refresh_token", label: "refresh_token" },
];

const AUTH_METHOD_OPTIONS = [
  { value: "client_secret_post", label: "client_secret_post (confidential)" },
  { value: "client_secret_basic", label: "client_secret_basic (confidential)" },
  { value: "none", label: "none (public client)" },
];

interface ClientFormData {
  name: string;
  redirect_uris: string;
  grant_types: string[];
  token_endpoint_auth_method: string;
  scope: string;
  is_agent: boolean;
  agent_description: string;
}

const emptyForm: ClientFormData = {
  name: "",
  redirect_uris: "",
  grant_types: ["authorization_code"],
  token_endpoint_auth_method: "client_secret_post",
  scope: "",
  is_agent: false,
  agent_description: "",
};

interface EditClientFormData {
  name: string;
  redirect_uris: string;
  grant_types: string[];
  scope: string;
}

export default function Clients() {
  const [clients, setClients] = useState<ClientView[]>([]);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selected, setSelected] = useState<ClientView | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState("");

  // Create client form state
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<ClientFormData>({ ...emptyForm });
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [creating, setCreating] = useState(false);

  // Secret display modal state
  const [createdResult, setCreatedResult] = useState<CreateClientResponse | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  // Rotate secret state
  const [rotatedResult, setRotatedResult] = useState<RotateSecretResponse | null>(null);
  const [rotatedSecretCopied, setRotatedSecretCopied] = useState(false);
  const [rotating, setRotating] = useState(false);

  // Edit client state
  const [showEdit, setShowEdit] = useState(false);
  const [editTarget, setEditTarget] = useState<ClientView | null>(null);
  const [editForm, setEditForm] = useState<EditClientFormData>({ name: "", redirect_uris: "", grant_types: [], scope: "" });
  const [editFormErrors, setEditFormErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const loadClients = useCallback(async () => {
    try {
      const data = await listClients({ limit: 200 });
      setClients(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load clients");
    }
  }, []);

  useEffect(() => {
    loadClients();
  }, [loadClients]);

  const filtered = clients.filter((c) => {
    const type = clientType(c);
    if (typeFilter !== "all" && type !== typeFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return c.name.toLowerCase().includes(s) || c.id.toLowerCase().includes(s);
    }
    return true;
  });

  const handleSuspend = async (id: string) => {
    try {
      await suspendClient(id);
      showToast("Client suspended");
      setSelected(null);
      loadClients();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed");
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await revokeClient(id);
      showToast("Client tokens revoked");
      setSelected(null);
      loadClients();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed");
    }
  };

  const handleReactivate = async (id: string) => {
    try {
      await reactivateClient(id);
      showToast("Client reactivated");
      setSelected(null);
      loadClients();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed");
    }
  };

  const openCreateForm = () => {
    setForm({ ...emptyForm });
    setFormErrors({});
    setShowCreate(true);
  };

  const toggleGrantType = (gt: string) => {
    setForm((f) => {
      const current = f.grant_types;
      if (current.includes(gt)) {
        return { ...f, grant_types: current.filter((g) => g !== gt) };
      }
      return { ...f, grant_types: [...current, gt] };
    });
  };

  const validateForm = (): boolean => {
    const e: Record<string, string> = {};
    if (!form.name.trim()) e.name = "Client name is required";
    if (form.grant_types.length === 0) e.grant_types = "Select at least one grant type";
    if (!form.token_endpoint_auth_method) e.auth_method = "Select an auth method";
    if (form.is_agent && !form.agent_description.trim()) e.agent_description = "Agent description is required when agent is enabled";
    // Redirect URIs are required for authorization_code grant
    if (form.grant_types.includes("authorization_code")) {
      const uris = form.redirect_uris.split(",").map((s) => s.trim()).filter(Boolean);
      if (uris.length === 0) e.redirect_uris = "At least one redirect URI is required for authorization_code grant";
    }
    setFormErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleCreate = async () => {
    if (!validateForm()) return;
    setCreating(true);
    try {
      const uris = form.redirect_uris.split(",").map((s) => s.trim()).filter(Boolean);
      // Derive response_types from grant_types
      const responseTypes: string[] = [];
      if (form.grant_types.includes("authorization_code")) responseTypes.push("code");
      const resp = await createClient({
        client_name: form.name.trim(),
        redirect_uris: uris,
        grant_types: form.grant_types,
        response_types: responseTypes,
        token_endpoint_auth_method: form.token_endpoint_auth_method,
        scope: form.scope.trim(),
        agent: form.is_agent,
        agent_description: form.agent_description.trim(),
      });
      setShowCreate(false);
      setCreatedResult(resp);
      setSecretCopied(false);
      loadClients();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to create client");
    } finally {
      setCreating(false);
    }
  };

  const handleCopySecret = async () => {
    if (!createdResult?.client_secret) return;
    try {
      await navigator.clipboard.writeText(createdResult.client_secret);
      setSecretCopied(true);
      setTimeout(() => setSecretCopied(false), 2000);
    } catch {
      // Fallback: select the text for manual copy
      showToast("Copy failed — please select and copy manually");
    }
  };

  const handleDismissSecret = () => {
    setCreatedResult(null);
    showToast("Client created successfully");
  };

  const handleRotateSecret = async (id: string) => {
    setRotating(true);
    try {
      const resp = await rotateClientSecret(id);
      setRotatedResult(resp);
      setRotatedSecretCopied(false);
      setSelected(null);
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to rotate secret");
    } finally {
      setRotating(false);
    }
  };

  const handleCopyRotatedSecret = async () => {
    if (!rotatedResult?.client_secret) return;
    try {
      await navigator.clipboard.writeText(rotatedResult.client_secret);
      setRotatedSecretCopied(true);
      setTimeout(() => setRotatedSecretCopied(false), 2000);
    } catch {
      showToast("Copy failed — please select and copy manually");
    }
  };

  const handleDismissRotatedSecret = () => {
    setRotatedResult(null);
    showToast("Client secret rotated successfully");
  };

  const openEditForm = (client: ClientView) => {
    setEditTarget(client);
    setEditForm({
      name: client.name,
      redirect_uris: client.redirect_uris.join(", "),
      grant_types: [...client.grant_types],
      scope: "", // scope is not exposed on ClientView; user fills in if needed
    });
    setEditFormErrors({});
    setSelected(null);
    setShowEdit(true);
  };

  const toggleEditGrantType = (gt: string) => {
    setEditForm((f) => {
      const current = f.grant_types;
      if (current.includes(gt)) {
        return { ...f, grant_types: current.filter((g) => g !== gt) };
      }
      return { ...f, grant_types: [...current, gt] };
    });
  };

  const validateEditForm = (): boolean => {
    const e: Record<string, string> = {};
    if (!editForm.name.trim()) e.name = "Client name is required";
    if (editForm.grant_types.length === 0) e.grant_types = "Select at least one grant type";
    if (editForm.grant_types.includes("authorization_code")) {
      const uris = editForm.redirect_uris.split(",").map((s) => s.trim()).filter(Boolean);
      if (uris.length === 0) e.redirect_uris = "At least one redirect URI is required for authorization_code grant";
    }
    setEditFormErrors(e);
    return Object.keys(e).length === 0;
  };

  const handleEdit = async () => {
    if (!editTarget || !validateEditForm()) return;
    setSaving(true);
    try {
      const uris = editForm.redirect_uris.split(",").map((s) => s.trim()).filter(Boolean);
      const req: UpdateClientRequest = {};
      // Only include fields that changed
      if (editForm.name.trim() !== editTarget.name) {
        req.client_name = editForm.name.trim();
      }
      const oldUris = editTarget.redirect_uris.join(", ");
      const newUris = uris.join(", ");
      if (newUris !== oldUris) {
        req.redirect_uris = uris;
      }
      if (JSON.stringify(editForm.grant_types.sort()) !== JSON.stringify([...editTarget.grant_types].sort())) {
        req.grant_types = editForm.grant_types;
      }
      if (editForm.scope.trim()) {
        req.scope = editForm.scope.trim();
      }
      // Only call API if there are actual changes
      if (Object.keys(req).length === 0) {
        showToast("No changes to save");
        setShowEdit(false);
        return;
      }
      await updateClient(editTarget.id, req);
      setShowEdit(false);
      setEditTarget(null);
      showToast("Client updated successfully");
      loadClients();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to update client");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <div style={{ fontSize: sz.xl, fontWeight: 600, fontFamily: fonts.mono }}>Clients</div>
          <div style={{ fontSize: sz.base, color: C.textDim, marginTop: 2 }}>
            {clients.length} registered OAuth clients
          </div>
        </div>
        <Btn onClick={openCreateForm}>+ Create Client</Btn>
      </div>

      {error && (
        <div style={{ marginBottom: 14, padding: "8px 14px", background: alpha(C.danger, 0x12), border: `1px solid ${alpha(C.danger, 0x40)}`, borderRadius: 6, fontSize: sz.base, color: C.danger }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
        <TextInput placeholder="Search by name or ID…" value={search} onChange={setSearch} style={{ width: 260 }} />
        <div style={{ display: "flex", gap: 4 }}>
          {["all", "public", "confidential", "agent"].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              style={{
                padding: "5px 12px",
                borderRadius: 5,
                border: `1px solid ${typeFilter === t ? alpha(t === "agent" ? C.purple : C.accent, 0x50) : C.border2}`,
                background: typeFilter === t ? alpha(t === "agent" ? C.purple : C.accent, 0x18) : "transparent",
                color: typeFilter === t ? (t === "agent" ? C.purple : C.accent) : C.textDim,
                cursor: "pointer",
                fontFamily: fonts.mono,
                fontSize: sz.sm,
                textTransform: "uppercase",
              }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <Card style={{ padding: 0 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: sz.base }}>
          <thead>
            <tr>
              {["ID", "Name", "Type", "Grant Types", "Status", "Updated"].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "8px 12px", color: C.textDim, fontFamily: fonts.mono, fontSize: sz.xs, textTransform: "uppercase", letterSpacing: 1.2, borderBottom: `1px solid ${C.border}`, fontWeight: 400 }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => {
              const type = clientType(c);
              return (
                <tr
                  key={c.id}
                  onClick={() => setSelected(c)}
                  style={{ cursor: "pointer", borderBottom: `1px solid ${C.border}`, transition: "background 0.1s" }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = C.surface2; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                >
                  <td style={{ padding: "10px 12px" }}><Mono>{truncate(c.id)}</Mono></td>
                  <td style={{ padding: "10px 12px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontWeight: 500 }}>{c.name}</span>
                      {type === "agent" && <Tag color={C.purple}>agent</Tag>}
                    </div>
                  </td>
                  <td style={{ padding: "10px 12px" }}><Tag color={typeColor(type)}>{type}</Tag></td>
                  <td style={{ padding: "10px 12px" }}><Mono style={{ fontSize: sz.sm }}>{c.grant_types.join(", ")}</Mono></td>
                  <td style={{ padding: "10px 12px" }}><StatusDot status={c.status} /><span style={{ fontSize: sz.base, color: C.textDim }}>{c.status}</span></td>
                  <td style={{ padding: "10px 12px" }}><span style={{ fontSize: sz.base, color: C.textDim }}>{formatDate(c.updated_at)}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ padding: "20px 12px", fontSize: sz.base, color: C.textDim, textAlign: "center" }}>
            {clients.length === 0 ? "No clients registered." : "No clients match your filters."}
          </div>
        )}
      </Card>

      {/* Client Detail Drawer */}
      {selected && (
        <Drawer title="Client Detail" subtitle={selected.name} onClose={() => setSelected(null)} width={500}>
          <DrawerRow label="client_id" value={<Mono style={{ fontSize: sz.sm }}>{selected.id}</Mono>} />
          <DrawerRow label="name" value={selected.name} />
          <DrawerRow label="type" value={<Tag color={typeColor(clientType(selected))}>{clientType(selected)}</Tag>} />
          <DrawerRow label="grant_types" value={
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {selected.grant_types.map((g) => <Tag key={g} color={C.blue}>{g}</Tag>)}
            </div>
          } />
          <DrawerRow label="response_types" value={
            <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {selected.response_types.map((r) => <Tag key={r} color={C.textDim}>{r}</Tag>)}
            </div>
          } />
          <DrawerRow label="auth_method" value={<Mono>{selected.token_endpoint_auth_method}</Mono>} />
          <DrawerRow label="status" value={<><StatusDot status={selected.status} />{selected.status}</>} />
          <DrawerRow label="redirect_uris" value={
            selected.redirect_uris.length > 0
              ? <div>{selected.redirect_uris.map((u) => <div key={u}><Mono style={{ fontSize: sz.sm }}>{u}</Mono></div>)}</div>
              : <span style={{ color: C.textDim }}>none</span>
          } />
          <DrawerRow label="registration" value={selected.registration_source} />
          <DrawerRow label="issued_at" value={formatDate(selected.issued_at)} />
          <DrawerRow label="updated_at" value={formatDate(selected.updated_at)} />
          {selected.cimd_url && <DrawerRow label="cimd_url" value={<Mono style={{ fontSize: sz.sm }}>{selected.cimd_url}</Mono>} />}

          <div style={{ marginTop: 20 }}>
            <SectionTitle>Actions</SectionTitle>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <Btn secondary small full onClick={() => openEditForm(selected)}>Edit Client</Btn>
              {selected.token_endpoint_auth_method !== "none" && (
                <Btn secondary small full onClick={() => handleRotateSecret(selected.id)} disabled={rotating}>
                  {rotating ? "Rotating..." : "Rotate Secret"}
                </Btn>
              )}
              {selected.status === "active" ? (
                <Btn secondary small full onClick={() => handleSuspend(selected.id)}>Suspend Client</Btn>
              ) : selected.status === "suspended" ? (
                <Btn secondary small full onClick={() => handleReactivate(selected.id)}>Reactivate Client</Btn>
              ) : null}
              <Btn danger small full onClick={() => handleRevoke(selected.id)}>Revoke All Tokens</Btn>
            </div>
          </div>
        </Drawer>
      )}

      {/* Create Client Drawer */}
      {showCreate && (
        <Drawer title="Create Client" onClose={() => setShowCreate(false)} width={520}>
          <div style={{ display: "grid", gap: 16 }}>
            <div>
              <Label>Client Name *</Label>
              <TextInput placeholder="e.g. My MCP App" value={form.name} onChange={(v) => setForm((f) => ({ ...f, name: v }))} />
              {formErrors.name && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{formErrors.name}</div>}
            </div>

            <div>
              <Label>Redirect URIs (comma-separated)</Label>
              <TextInput placeholder="e.g. http://localhost:3000/callback, https://app.example.com/callback" value={form.redirect_uris} onChange={(v) => setForm((f) => ({ ...f, redirect_uris: v }))} />
              {formErrors.redirect_uris && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{formErrors.redirect_uris}</div>}
              <div style={{ fontSize: sz.sm, color: C.textDim, marginTop: 4 }}>Required for authorization_code grant. Exact match enforced.</div>
            </div>

            <div>
              <Label>Grant Types *</Label>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {GRANT_TYPE_OPTIONS.map((gt) => (
                  <button
                    key={gt.value}
                    onClick={() => toggleGrantType(gt.value)}
                    style={{
                      padding: "6px 14px",
                      borderRadius: 5,
                      border: `1px solid ${form.grant_types.includes(gt.value) ? alpha(C.accent, 0x50) : C.border2}`,
                      background: form.grant_types.includes(gt.value) ? alpha(C.accent, 0x18) : "transparent",
                      color: form.grant_types.includes(gt.value) ? C.accent : C.textDim,
                      cursor: "pointer",
                      fontFamily: fonts.mono,
                      fontSize: sz.sm,
                    }}
                  >
                    {gt.label}
                  </button>
                ))}
              </div>
              {formErrors.grant_types && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{formErrors.grant_types}</div>}
            </div>

            <div>
              <Label>Token Endpoint Auth Method *</Label>
              <select
                value={form.token_endpoint_auth_method}
                onChange={(e) => setForm((f) => ({ ...f, token_endpoint_auth_method: e.target.value }))}
                style={{
                  width: "100%",
                  padding: "6px 12px",
                  background: C.surface2,
                  border: `1px solid ${C.border2}`,
                  borderRadius: 5,
                  color: C.text,
                  fontSize: sz.base,
                  fontFamily: fonts.mono,
                  outline: "none",
                  boxSizing: "border-box",
                }}
              >
                {AUTH_METHOD_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
              {formErrors.auth_method && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{formErrors.auth_method}</div>}
              <div style={{ fontSize: sz.sm, color: C.textDim, marginTop: 4 }}>
                {form.token_endpoint_auth_method === "none"
                  ? "Public client — no secret will be generated."
                  : "Confidential client — a client_secret will be generated once."}
              </div>
            </div>

            <div>
              <Label>Scope (space-separated)</Label>
              <TextInput placeholder="e.g. read write admin" value={form.scope} onChange={(v) => setForm((f) => ({ ...f, scope: v }))} />
              <div style={{ fontSize: sz.sm, color: C.textDim, marginTop: 4 }}>Optional. Leave blank for no scope restriction.</div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0" }}>
              <Toggle checked={form.is_agent} onChange={(v) => setForm((f) => ({ ...f, is_agent: v }))} />
              <div style={{ fontSize: sz.base, color: C.textDim }}>{form.is_agent ? "Agent client — acts as an MCP agent" : "Standard OAuth client"}</div>
            </div>

            {form.is_agent && (
              <div>
                <Label>Agent Description *</Label>
                <TextInput rows={2} placeholder="Describe what this agent does..." value={form.agent_description} onChange={(v) => setForm((f) => ({ ...f, agent_description: v }))} />
                {formErrors.agent_description && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{formErrors.agent_description}</div>}
              </div>
            )}
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 24, paddingTop: 16, borderTop: `1px solid ${C.border}` }}>
            <Btn secondary onClick={() => setShowCreate(false)}>Cancel</Btn>
            <Btn onClick={handleCreate} disabled={creating}>{creating ? "Creating..." : "Create Client"}</Btn>
          </div>
        </Drawer>
      )}

      {/* Edit Client Drawer */}
      {showEdit && editTarget && (
        <Drawer title="Edit Client" subtitle={editTarget.name} onClose={() => setShowEdit(false)} width={520}>
          <div style={{ display: "grid", gap: 16 }}>
            <div>
              <Label>Client Name *</Label>
              <TextInput placeholder="e.g. My MCP App" value={editForm.name} onChange={(v) => setEditForm((f) => ({ ...f, name: v }))} />
              {editFormErrors.name && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{editFormErrors.name}</div>}
            </div>

            <div>
              <Label>Redirect URIs (comma-separated)</Label>
              <TextInput placeholder="e.g. http://localhost:3000/callback, https://app.example.com/callback" value={editForm.redirect_uris} onChange={(v) => setEditForm((f) => ({ ...f, redirect_uris: v }))} />
              {editFormErrors.redirect_uris && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{editFormErrors.redirect_uris}</div>}
              <div style={{ fontSize: sz.sm, color: C.textDim, marginTop: 4 }}>Required for authorization_code grant. Exact match enforced.</div>
            </div>

            <div>
              <Label>Grant Types *</Label>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {GRANT_TYPE_OPTIONS.map((gt) => (
                  <button
                    key={gt.value}
                    onClick={() => toggleEditGrantType(gt.value)}
                    style={{
                      padding: "6px 14px",
                      borderRadius: 5,
                      border: `1px solid ${editForm.grant_types.includes(gt.value) ? alpha(C.accent, 0x50) : C.border2}`,
                      background: editForm.grant_types.includes(gt.value) ? alpha(C.accent, 0x18) : "transparent",
                      color: editForm.grant_types.includes(gt.value) ? C.accent : C.textDim,
                      cursor: "pointer",
                      fontFamily: fonts.mono,
                      fontSize: sz.sm,
                    }}
                  >
                    {gt.label}
                  </button>
                ))}
              </div>
              {editFormErrors.grant_types && <div style={{ fontSize: sz.sm, color: C.danger, marginTop: 3 }}>{editFormErrors.grant_types}</div>}
            </div>

            <div>
              <Label>Scope (space-separated)</Label>
              <TextInput placeholder="e.g. read write admin" value={editForm.scope} onChange={(v) => setEditForm((f) => ({ ...f, scope: v }))} />
              <div style={{ fontSize: sz.sm, color: C.textDim, marginTop: 4 }}>Optional. Leave blank to keep existing scope unchanged.</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 24, paddingTop: 16, borderTop: `1px solid ${C.border}` }}>
            <Btn secondary onClick={() => setShowEdit(false)}>Cancel</Btn>
            <Btn onClick={handleEdit} disabled={saving}>{saving ? "Saving..." : "Save Changes"}</Btn>
          </div>
        </Drawer>
      )}

      {/* Client Secret Display Modal — shown once after creation */}
      {createdResult && (
        <Modal title="Client Created" titleColor={C.success} width={540} onClose={handleDismissSecret}>
          <div style={{ fontSize: sz.base, color: C.textDim, lineHeight: 1.8, marginBottom: 16 }}>
            <strong style={{ color: C.text }}>{createdResult.client_name}</strong> has been created.
          </div>

          <div style={{ marginBottom: 12 }}>
            <Label>Client ID</Label>
            <div style={{
              padding: "8px 12px",
              background: C.surface2,
              border: `1px solid ${C.border2}`,
              borderRadius: 5,
              fontFamily: fonts.mono,
              fontSize: sz.sm,
              color: C.text,
              wordBreak: "break-all",
            }}>
              {createdResult.client_id}
            </div>
          </div>

          {createdResult.client_secret && (
            <div style={{ marginBottom: 16 }}>
              <Label>Client Secret</Label>
              <div style={{
                padding: "10px 12px",
                background: alpha(C.warn, 0x12),
                border: `1px solid ${alpha(C.warn, 0x40)}`,
                borderRadius: 5,
                marginBottom: 8,
              }}>
                <div style={{
                  fontFamily: fonts.mono,
                  fontSize: sz.sm,
                  color: C.text,
                  wordBreak: "break-all",
                  marginBottom: 8,
                  userSelect: "all",
                }}>
                  {createdResult.client_secret}
                </div>
                <Btn small onClick={handleCopySecret}>
                  {secretCopied ? "Copied!" : "Copy to Clipboard"}
                </Btn>
              </div>
              <div style={{
                fontSize: sz.sm,
                color: C.warn,
                fontWeight: 600,
                lineHeight: 1.6,
              }}>
                This secret is shown only once. Copy it now — it cannot be retrieved later.
              </div>
            </div>
          )}

          {!createdResult.client_secret && (
            <div style={{
              padding: "8px 14px",
              background: alpha(C.blue, 0x12),
              border: `1px solid ${alpha(C.blue, 0x40)}`,
              borderRadius: 6,
              fontSize: sz.sm,
              color: C.blue,
              marginBottom: 16,
            }}>
              Public client — no client secret was generated.
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
            <Btn onClick={handleDismissSecret}>Done</Btn>
          </div>
        </Modal>
      )}

      {/* Rotated Secret Display Modal — shown once after rotation */}
      {rotatedResult && (
        <Modal title="Secret Rotated" titleColor={C.success} width={540} onClose={handleDismissRotatedSecret}>
          <div style={{ fontSize: sz.base, color: C.textDim, lineHeight: 1.8, marginBottom: 16 }}>
            The client secret for <Mono style={{ fontSize: sz.sm }}>{rotatedResult.client_id}</Mono> has been rotated.
          </div>

          <div style={{ marginBottom: 12 }}>
            <Label>Client ID</Label>
            <div style={{
              padding: "8px 12px",
              background: C.surface2,
              border: `1px solid ${C.border2}`,
              borderRadius: 5,
              fontFamily: fonts.mono,
              fontSize: sz.sm,
              color: C.text,
              wordBreak: "break-all",
            }}>
              {rotatedResult.client_id}
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <Label>New Client Secret</Label>
            <div style={{
              padding: "10px 12px",
              background: alpha(C.warn, 0x12),
              border: `1px solid ${alpha(C.warn, 0x40)}`,
              borderRadius: 5,
              marginBottom: 8,
            }}>
              <div style={{
                fontFamily: fonts.mono,
                fontSize: sz.sm,
                color: C.text,
                wordBreak: "break-all",
                marginBottom: 8,
                userSelect: "all",
              }}>
                {rotatedResult.client_secret}
              </div>
              <Btn small onClick={handleCopyRotatedSecret}>
                {rotatedSecretCopied ? "Copied!" : "Copy to Clipboard"}
              </Btn>
            </div>
            <div style={{
              fontSize: sz.sm,
              color: C.warn,
              fontWeight: 600,
              lineHeight: 1.6,
            }}>
              This secret is shown only once. Copy it now — it cannot be retrieved later.
              The previous secret has been invalidated.
            </div>
          </div>

          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
            <Btn onClick={handleDismissRotatedSecret}>Done</Btn>
          </div>
        </Modal>
      )}

      <Toast message={toast} />
    </div>
  );
}

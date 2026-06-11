import { useState } from "react";
import { C, fonts, sz, alpha } from "../../tokens";
import Card from "../../components/Card";
import SectionTitle from "../../components/SectionTitle";
import Btn from "../../components/Btn";
import TextInput from "../../components/TextInput";
import Tag from "../../components/Tag";
import Mono from "../../components/Mono";
import AgentChain from "../../components/AgentChain";
import DelegationDepth from "../../components/DelegationDepth";

interface DecodedJWT {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  error?: string;
}

function decodeJWT(token: string): DecodedJWT {
  try {
    const parts = token.trim().split(".");
    if (parts.length !== 3) {
      return { header: {}, payload: {}, error: "Invalid JWT format — expected 3 dot-separated parts" };
    }

    const decodeBase64Url = (s: string): string => {
      let base64 = s.replace(/-/g, "+").replace(/_/g, "/");
      while (base64.length % 4) base64 += "=";
      return atob(base64);
    };

    const header = JSON.parse(decodeBase64Url(parts[0]));
    const payload = JSON.parse(decodeBase64Url(parts[1]));
    return { header, payload };
  } catch {
    return { header: {}, payload: {}, error: "Failed to decode JWT — invalid base64 or JSON" };
  }
}

function formatTimestamp(ts: unknown): string {
  if (typeof ts !== "number") return String(ts);
  return new Date(ts * 1000).toISOString();
}

function isExpired(exp: unknown): boolean {
  if (typeof exp !== "number") return false;
  return exp * 1000 < Date.now();
}

function timeRemaining(exp: unknown): string {
  if (typeof exp !== "number") return "—";
  const diff = exp * 1000 - Date.now();
  if (diff <= 0) return "expired";
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m remaining`;
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hrs}h ${remMins}m remaining`;
}

export default function InspectorTab() {
  const [token, setToken] = useState("");
  const [result, setResult] = useState<DecodedJWT | null>(null);

  const handleDecode = () => {
    if (!token.trim()) return;
    setResult(decodeJWT(token));
  };

  const handleClear = () => {
    setToken("");
    setResult(null);
  };

  const p = result?.payload || {};
  const h = result?.header || {};
  const expired = isExpired(p.exp);

  return (
    <div style={{ maxWidth: 720 }}>
      <div style={{ fontSize: sz.base, color: C.textDim, marginBottom: 18 }}>
        Decode any JWT to inspect its claims — decoded locally, never sent to the server
      </div>

      <Card style={{ marginBottom: 14 }}>
        <SectionTitle>Paste Token</SectionTitle>
        <TextInput
          rows={4}
          placeholder="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9…"
          value={token}
          onChange={setToken}
        />
        <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
          <Btn onClick={handleDecode} disabled={!token.trim()}>Decode</Btn>
          {token && <Btn secondary small onClick={handleClear}>Clear</Btn>}
        </div>
      </Card>

      {result && (
        <Card>
          {result.error ? (
            <div style={{ fontFamily: fonts.mono, fontSize: sz.base, color: C.danger }}>{result.error}</div>
          ) : (
            <>
              {/* Status tags */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
                <SectionTitle>Decoded Claims</SectionTitle>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <Tag color={expired ? C.danger : C.success}>{expired ? "● expired" : "● valid"}</Tag>
                  {!!p.cnf && <Tag color={C.purple}>dpop-bound</Tag>}
                  {!!p.agent_id && <Tag color={C.purple}>agent</Tag>}
                  {!!p.act && <Tag color={C.blue}>delegated</Tag>}
                </div>
              </div>

              {/* Expiry bar */}
              {typeof p.exp === "number" && typeof p.iat === "number" && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontFamily: fonts.mono, fontSize: sz.sm, color: C.textDim, marginBottom: 6 }}>
                    <span>{formatTimestamp(p.iat)}</span>
                    <span style={{ color: expired ? C.danger : C.success }}>{timeRemaining(p.exp)}</span>
                    <span>{formatTimestamp(p.exp)}</span>
                  </div>
                  <div style={{ height: 4, background: C.surface2, borderRadius: 2, overflow: "hidden" }}>
                    <div style={{
                      height: "100%",
                      width: expired ? "100%" : `${Math.max(0, Math.min(100, ((Date.now() / 1000 - (p.iat as number)) / ((p.exp as number) - (p.iat as number))) * 100))}%`,
                      background: expired ? C.danger : C.success,
                      borderRadius: 2,
                    }} />
                  </div>
                </div>
              )}

              {/* Header */}
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: sz.xs, fontFamily: fonts.mono, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
                  Header
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
                  {Object.entries(h).map(([k, v]) => (
                    <div key={k} style={{ display: "grid", gridTemplateColumns: "80px 1fr", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.textDim, textTransform: "uppercase" }}>{k}</span>
                      <Mono style={{ fontSize: sz.sm }}>{String(v)}</Mono>
                    </div>
                  ))}
                </div>
              </div>

              {/* Standard claims */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
                {([
                  ["sub", p.sub],
                  ["email", p.email],
                  ["client_id", p.client_id],
                  ["iss", p.iss],
                  ["jti", p.jti],
                  ["iat", p.iat ? formatTimestamp(p.iat) : undefined],
                  ["exp", p.exp ? formatTimestamp(p.exp) : undefined],
                ] as [string, unknown][]).filter(([, v]) => v !== undefined).map(([k, v]) => (
                  <div key={k} style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                    <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.textDim, textTransform: "uppercase", letterSpacing: 0.8 }}>{k}</span>
                    <Mono style={{ fontSize: sz.sm, wordBreak: "break-all" }}>{String(v)}</Mono>
                  </div>
                ))}
              </div>

              {/* Scope */}
              {p.scope && (
                <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                  <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.textDim, textTransform: "uppercase", letterSpacing: 0.8 }}>scope</span>
                  <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                    {String(p.scope).split(" ").map((s) => <Tag key={s} color={C.blue}>{s}</Tag>)}
                  </div>
                </div>
              )}

              {/* DPoP — cnf.jkt */}
              {p.cnf && typeof p.cnf === "object" && (p.cnf as Record<string, unknown>).jkt && (
                <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "10px 0", borderBottom: `1px solid ${C.border}`, borderTop: `1px solid ${alpha(C.purple, 0x30)}`, marginTop: 8 }}>
                  <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.purple, textTransform: "uppercase", letterSpacing: 0.8 }}>cnf.jkt</span>
                  <Mono style={{ color: C.purple, fontSize: sz.sm, wordBreak: "break-all" }}>
                    {String((p.cnf as Record<string, unknown>).jkt)}
                  </Mono>
                </div>
              )}

              {/* Token Exchange — act */}
              {p.act && typeof p.act === "object" && (
                <>
                  <div style={{ paddingTop: 8, paddingBottom: 4 }}>
                    <span style={{ fontSize: sz.xs, fontFamily: fonts.mono, textTransform: "uppercase", letterSpacing: 1.2, color: C.blue }}>
                      Token Exchange
                    </span>
                  </div>
                  {([
                    ["act.sub", (p.act as Record<string, unknown>).sub],
                    ["act.client_id", (p.act as Record<string, unknown>).client_id],
                  ] as [string, unknown][]).filter(([, v]) => v !== undefined).map(([k, v]) => (
                    <div key={k} style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.blue, textTransform: "uppercase", letterSpacing: 0.8 }}>{k}</span>
                      <Mono style={{ fontSize: sz.sm }}>{String(v)}</Mono>
                    </div>
                  ))}
                  {typeof p.delegation_depth === "number" && (
                    <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.blue, textTransform: "uppercase", letterSpacing: 0.8 }}>depth</span>
                      <DelegationDepth depth={p.delegation_depth} />
                    </div>
                  )}
                </>
              )}

              {/* Agent Identity */}
              {p.agent_id && (
                <>
                  <div style={{ paddingTop: 8, paddingBottom: 4 }}>
                    <span style={{ fontSize: sz.xs, fontFamily: fonts.mono, textTransform: "uppercase", letterSpacing: 1.2, color: C.purple }}>
                      Agent Identity
                    </span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                    <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.purple, textTransform: "uppercase", letterSpacing: 0.8 }}>agent_id</span>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <Tag color={C.purple}>agent</Tag>
                      <Mono style={{ fontSize: sz.sm }}>{String(p.agent_id)}</Mono>
                    </div>
                  </div>
                  {Array.isArray(p.agent_chain) && (
                    <div style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "7px 0", borderBottom: `1px solid ${C.border}` }}>
                      <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.purple, textTransform: "uppercase", letterSpacing: 0.8 }}>agent_chain</span>
                      <AgentChain chain={p.agent_chain as string[]} />
                    </div>
                  )}
                </>
              )}

              {/* Any other claims not already shown */}
              {(() => {
                const shown = new Set(["sub", "email", "client_id", "iss", "jti", "iat", "exp", "scope", "cnf", "act", "delegation_depth", "agent_id", "agent_chain", "may_act"]);
                const extra = Object.entries(p).filter(([k]) => !shown.has(k));
                if (extra.length === 0) return null;
                return (
                  <div style={{ marginTop: 12 }}>
                    <div style={{ fontSize: sz.xs, fontFamily: fonts.mono, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
                      Other Claims
                    </div>
                    {extra.map(([k, v]) => (
                      <div key={k} style={{ display: "grid", gridTemplateColumns: "100px 1fr", gap: 8, padding: "6px 0", borderBottom: `1px solid ${C.border}` }}>
                        <span style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.textDim, textTransform: "uppercase" }}>{k}</span>
                        <Mono style={{ fontSize: sz.sm, wordBreak: "break-all" }}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</Mono>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </>
          )}
        </Card>
      )}
    </div>
  );
}

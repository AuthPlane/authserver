import { useState, useEffect, useCallback } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { getStats, getSystemStatus, getSystemConfig, queryAudit } from "../api";
import type { StatsResponse, SystemStatusResponse, SystemConfigResponse, AuditEvent } from "../api";
import Card from "../components/Card";
import Label from "../components/Label";
import SectionTitle from "../components/SectionTitle";
import StatusDot from "../components/StatusDot";
import Tag from "../components/Tag";
import Mono from "../components/Mono";
import Table from "../components/Table";
import InfoBox from "../components/InfoBox";

// Event color mapping for audit events
function eventColor(event: string): string {
  if (event.includes("agent.") || event.includes("token.exchanged")) return C.purple;
  if (event.includes("vended") || event.includes("token_issued")) return C.success;
  if (event.includes("created")) return C.blue;
  if (event.includes("rotated") || event.includes("updated")) return C.accent;
  if (event.includes("deleted") || event.includes("suspended") || event.includes("revoked") || event.includes("rejected")) return C.danger;
  if (event.includes("dpop.")) return C.warn;
  return C.textDim;
}

function formatRelativeTime(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export default function Overview() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [status, setStatus] = useState<SystemStatusResponse | null>(null);
  const [config, setConfig] = useState<SystemConfigResponse | null>(null);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [s, st, cfg, a] = await Promise.all([
        getStats(),
        getSystemStatus(),
        getSystemConfig(),
        queryAudit({ limit: 7 }),
      ]);
      setStats(s);
      setStatus(st);
      setConfig(cfg);
      setAudit(a);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load data");
    }
  }, []);

  useEffect(() => {
    loadData();
    const iv = setInterval(loadData, 30000);
    return () => clearInterval(iv);
  }, [loadData]);

  return (
    <div style={{ padding: 28 }}>
      <div style={{ fontFamily: fonts.mono, fontSize: sz.xl, fontWeight: 600, marginBottom: 4 }}>
        Overview
      </div>
      <div style={{ fontSize: sz.base, color: C.textDim, marginBottom: 24 }}>
        {status ? `v${status.version} · up ${status.uptime} · 30s refresh` : "Loading…"}
      </div>

      {error && (
        <InfoBox color={C.danger}>
          <strong style={{ color: C.danger }}>Error:</strong> {error}
        </InfoBox>
      )}

      {/* Status cards —  dropped the legacy "Connectors" + "Vault
          Connections" cards. The replacement narrows the row to 3 cells:
          Signing Key + Encryption + Token Exchange. The Vault Connections
          stat has no replacement; if operators ask for a "Broker Grants"
          stat, file as a follow-up admin-stats extension PR. */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 14, marginBottom: 20 }}>
        <Card>
          <Label>Signing Key</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.xl, color: C.accent, marginBottom: 4 }}>
            {config?.signing.algorithm || "—"}
          </div>
          <div style={{ fontSize: sz.base, color: C.textDim }}>
            {config?.signing.key_store || "—"}
          </div>
        </Card>
        <Card>
          <Label>Encryption</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.base, color: C.text, marginBottom: 4 }}>
            {config?.encryption.driver || "—"}
          </div>
          <div style={{ fontSize: sz.base }}>
            <StatusDot status={status?.subsystems.find(s => s.name === "encryption")?.status || "unknown"} />
            {status?.subsystems.find(s => s.name === "encryption")?.status || "unknown"}
          </div>
        </Card>
        <Card>
          <Label>Token Exchange</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.xl, color: C.text, marginBottom: 4 }}>
            {config?.token_exchange.enabled ? "enabled" : "disabled"}
          </div>
          <div style={{ fontSize: sz.base, color: C.textDim }}>
            {config?.token_exchange.enabled
              ? `max chain depth ${config.token_exchange.max_chain_depth}`
              : "configure token_exchange to enable"}
          </div>
        </Card>
      </div>

      {/* Quick stats */}
      {stats && (
        <div style={{
          display: "flex", gap: 32, marginBottom: 20, padding: "14px 20px",
          background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8, flexWrap: "wrap",
        }}>
          {[
            ["Clients", stats.clients],
            ["Users", stats.users],
            ["Tokens (24h)", stats.active_tokens_24h],
            ["Revoked", stats.revoked_tokens],
          ].map(([label, value]) => (
            <div key={label as string}>
              <div style={{ fontFamily: fonts.mono, fontSize: sz.xs, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 3 }}>
                {label}
              </div>
              <div style={{ fontFamily: fonts.mono, fontSize: sz.xxl, color: C.text }}>
                {value}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Alerts from system config */}
      {config && (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 20 }}>
          {config.dpop.enabled && (
            <div style={{ background: alpha(C.blue, 0x10), border: `1px solid ${alpha(C.blue, 0x30)}`, borderRadius: 6, padding: "10px 16px", fontSize: sz.base, color: C.textDim }}>
              <span style={{ color: C.blue, fontFamily: fonts.mono, fontSize: sz.xs, textTransform: "uppercase", letterSpacing: 1, marginRight: 8 }}>
                Info
              </span>
              DPoP enabled · nonce TTL {config.dpop.nonce_ttl || "default"}
              {config.agents.enabled && ` · agents enabled`}
            </div>
          )}
          {config.token_exchange.enabled && (
            <div style={{ background: alpha(C.purple, 0x10), border: `1px solid ${alpha(C.purple, 0x30)}`, borderRadius: 6, padding: "10px 16px", fontSize: sz.base, color: C.textDim }}>
              <span style={{ color: C.purple, fontFamily: fonts.mono, fontSize: sz.xs, textTransform: "uppercase", letterSpacing: 1, marginRight: 8 }}>
                Info
              </span>
              Token exchange enabled · max chain depth {config.token_exchange.max_chain_depth}
            </div>
          )}
        </div>
      )}

      {/* Recent audit events */}
      <Card>
        <SectionTitle>Recent Audit Events</SectionTitle>
        {audit.length === 0 ? (
          <div style={{ fontSize: sz.base, color: C.textDim, padding: "12px 0" }}>No recent events.</div>
        ) : (
          <Table
            headers={["Time", "Event", "Actor", "Detail"]}
            rows={audit.map((e) => [
              <Mono>{formatRelativeTime(e.created_at)}</Mono>,
              <Tag color={eventColor(e.action)}>{e.action}</Tag>,
              <Mono>{e.actor_id || "—"}</Mono>,
              <span style={{ fontSize: sz.base, color: C.textDim }}>{e.detail || "—"}</span>,
            ])}
          />
        )}
      </Card>
    </div>
  );
}

import { useState, useEffect, useCallback } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { queryAudit } from "../api";
import type { AuditEvent } from "../api";
import Card from "../components/Card";
import Tag from "../components/Tag";
import Mono from "../components/Mono";
import TextInput from "../components/TextInput";
import Btn from "../components/Btn";
import AgentChain from "../components/AgentChain";

function eventColor(event: string): string {
  if (event.includes("agent.") || event.includes("token.exchanged")) return C.purple;
  if (event.includes("vended") || event.includes("token_issued")) return C.success;
  if (event.includes("created")) return C.blue;
  if (event.includes("rotated") || event.includes("updated") || event.includes("connector.")) return C.accent;
  if (event.includes("deleted") || event.includes("suspended") || event.includes("revoked") || event.includes("rejected")) return C.danger;
  if (event.includes("dpop.")) return C.warn;
  return C.textDim;
}

function formatTime(iso: string): string {
  if (!iso) return "\u2014";
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatFull(iso: string): string {
  if (!iso) return "\u2014";
  return new Date(iso).toISOString();
}

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [actionFilter, setActionFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [limit] = useState(50);
  const [error, setError] = useState("");

  const loadEvents = useCallback(async () => {
    try {
      const data = await queryAudit({
        action: actionFilter || undefined,
        actor_id: actorFilter || undefined,
        limit,
      });
      setEvents(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load audit events");
    }
  }, [actionFilter, actorFilter, limit]);

  useEffect(() => {
    loadEvents();
    if (!autoRefresh) return;
    const iv = setInterval(loadEvents, 30000);
    return () => clearInterval(iv);
  }, [loadEvents, autoRefresh]);

  return (
    <div style={{ padding: 28 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <div>
          <div style={{ fontSize: sz.xl, fontWeight: 600, fontFamily: fonts.mono }}>Audit Log</div>
          <div style={{ fontSize: sz.base, color: C.textDim, marginTop: 2 }}>
            {events.length} events · {autoRefresh ? "30s auto-refresh" : "paused"}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            style={{
              padding: "5px 12px", borderRadius: 5,
              border: `1px solid ${autoRefresh ? alpha(C.success, 0x50) : C.border2}`,
              background: autoRefresh ? alpha(C.success, 0x18) : "transparent",
              color: autoRefresh ? C.success : C.textDim,
              cursor: "pointer", fontFamily: fonts.mono, fontSize: sz.sm,
            }}
          >
            {autoRefresh ? "\u25CF Live" : "\u25CB Paused"}
          </button>
          <Btn secondary small onClick={loadEvents}>Refresh</Btn>
        </div>
      </div>

      {error && (
        <div style={{ marginBottom: 14, padding: "8px 14px", background: alpha(C.danger, 0x12), border: `1px solid ${alpha(C.danger, 0x40)}`, borderRadius: 6, fontSize: sz.base, color: C.danger }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: 10, marginBottom: 14, flexWrap: "wrap" }}>
        <TextInput placeholder="Filter by action…" value={actionFilter} onChange={setActionFilter} style={{ width: 200 }} />
        <TextInput placeholder="Filter by actor ID…" value={actorFilter} onChange={setActorFilter} style={{ width: 200 }} />
      </div>

      <Card style={{ padding: 0 }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: sz.base }}>
          <thead>
            <tr>
              {["Timestamp", "Event", "Actor", "Detail", ""].map((h) => (
                <th key={h} style={{ textAlign: "left", padding: "10px 16px", color: C.textDim, fontFamily: fonts.mono, fontSize: sz.xs, textTransform: "uppercase", letterSpacing: 1.2, borderBottom: `1px solid ${C.border}`, fontWeight: 400 }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <>
                <tr
                  key={e.id || i}
                  onClick={() => setExpanded(expanded === i ? null : i)}
                  style={{
                    cursor: "pointer",
                    borderBottom: `1px solid ${C.border}`,
                    background: expanded === i ? C.surface2 : "transparent",
                  }}
                  onMouseEnter={(ev) => { if (expanded !== i) ev.currentTarget.style.background = C.surface2; }}
                  onMouseLeave={(ev) => { if (expanded !== i) ev.currentTarget.style.background = "transparent"; }}
                >
                  <td style={{ padding: "10px 16px" }}>
                    <Mono>{formatTime(e.created_at)}</Mono>
                  </td>
                  <td style={{ padding: "10px 16px" }}>
                    <Tag color={eventColor(e.action)}>{e.action}</Tag>
                  </td>
                  <td style={{ padding: "10px 16px" }}>
                    <Mono>{e.actor_id || "\u2014"}</Mono>
                  </td>
                  <td style={{ padding: "10px 16px", color: C.textDim }}>{e.detail || "\u2014"}</td>
                  <td style={{ padding: "10px 16px" }}>
                    <span style={{ fontSize: sz.xs, color: C.textDim }}>{expanded === i ? "\u25B2" : "\u25BC"}</span>
                  </td>
                </tr>
                {expanded === i && (
                  <tr key={`${e.id || i}-detail`} style={{ background: C.surface2 }}>
                    <td colSpan={5} style={{ padding: "12px 16px 16px" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
                        {[
                          ["event", e.action],
                          ["timestamp", formatFull(e.created_at)],
                          ["actor_id", e.actor_id || "\u2014"],
                          ["actor_type", e.actor_type || "\u2014"],
                          ["client_id", e.client_id || "\u2014"],
                          ["detail", e.detail || "\u2014"],
                        ].map(([k, v]) => (
                          <div key={k}>
                            <div style={{ fontSize: sz.xs, fontFamily: fonts.mono, color: C.textDim, textTransform: "uppercase", letterSpacing: 1, marginBottom: 2 }}>
                              {k}
                            </div>
                            <div style={{ fontFamily: fonts.mono, fontSize: sz.sm, color: C.textMono, wordBreak: "break-all" }}>
                              {v}
                            </div>
                          </div>
                        ))}
                        {/* Phase 3 metadata fields */}
                        {e.metadata && Object.keys(e.metadata).length > 0 &&
                          Object.entries(e.metadata).map(([k, v]) => (
                            <div key={k}>
                              <div style={{
                                fontSize: sz.xs, fontFamily: fonts.mono,
                                color: k.includes("agent") || k.includes("chain") ? C.purple : C.blue,
                                textTransform: "uppercase", letterSpacing: 1, marginBottom: 2,
                              }}>
                                {k}
                              </div>
                              <div style={{ fontFamily: fonts.mono, fontSize: sz.sm, color: C.textMono, wordBreak: "break-all" }}>
                                {Array.isArray(v) ? (
                                  <div style={{ marginTop: 4 }}>
                                    <AgentChain chain={v as string[]} />
                                  </div>
                                ) : (
                                  String(v)
                                )}
                              </div>
                            </div>
                          ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
        {events.length === 0 && (
          <div style={{ padding: "20px 16px", fontSize: sz.base, color: C.textDim, textAlign: "center" }}>
            No audit events found.
          </div>
        )}
      </Card>
    </div>
  );
}

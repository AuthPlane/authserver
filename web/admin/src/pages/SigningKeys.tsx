import { useState, useEffect } from "react";
import { C, fonts, sz } from "../tokens";
import { getSystemStatus, getSystemConfig } from "../api";
import type { SystemStatusResponse, SystemConfigResponse } from "../api";
import Card from "../components/Card";
import SectionTitle from "../components/SectionTitle";
import Label from "../components/Label";
import StatusDot from "../components/StatusDot";
import Tag from "../components/Tag";
import Mono from "../components/Mono";
import Btn from "../components/Btn";
import InfoBox from "../components/InfoBox";

export default function SigningKeys() {
  const [status, setStatus] = useState<SystemStatusResponse | null>(null);
  const [config, setConfig] = useState<SystemConfigResponse | null>(null);
  const [jwksResult, setJwksResult] = useState<string | null>(null);
  const [jwksLoading, setJwksLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([getSystemStatus(), getSystemConfig()])
      .then(([s, c]) => { setStatus(s); setConfig(c); })
      .catch(err => setError(err instanceof Error ? err.message : "Failed to load"));
  }, []);

  const signingSubsystem = status?.subsystems.find(s => s.name === "signing");

  const testJWKS = async () => {
    setJwksLoading(true);
    try {
      const res = await fetch("/.well-known/jwks.json");
      const data = await res.json();
      setJwksResult(JSON.stringify(data, null, 2));
    } catch {
      setJwksResult("Failed to fetch JWKS endpoint");
    } finally {
      setJwksLoading(false);
    }
  };

  return (
    <div style={{ padding: 28, maxWidth: 720 }}>
      <div style={{ fontSize: sz.xl, fontWeight: 600, fontFamily: fonts.mono, marginBottom: 4 }}>
        Signing Keys
      </div>
      <div style={{ fontSize: sz.base, color: C.textDim, marginBottom: 20 }}>
        JWT signing key management
      </div>

      {error && (
        <div style={{ marginBottom: 14 }}>
          <InfoBox color={C.danger}>{error}</InfoBox>
        </div>
      )}

      {/* Key store status */}
      <div style={{ display: "flex", gap: 16, marginBottom: 18, flexWrap: "wrap" }}>
        <span style={{ fontFamily: fonts.mono, fontSize: sz.base }}>
          <StatusDot status={signingSubsystem?.status || "unknown"} />
          Key Store: {config?.signing.key_store || "—"}
        </span>
        <span style={{ fontFamily: fonts.mono, fontSize: sz.base }}>
          <StatusDot status="healthy" />
          JWKS: <span style={{ color: C.blue }}>/.well-known/jwks.json</span>
        </span>
        <Btn secondary small onClick={testJWKS} disabled={jwksLoading}>
          {jwksLoading ? "Testing…" : "Test JWKS"}
        </Btn>
      </div>

      {/* Current key card */}
      <Card style={{ marginBottom: 14 }}>
        <SectionTitle>Current Key</SectionTitle>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 16 }}>
          <div>
            <Label>Algorithm</Label>
            <div style={{ fontFamily: fonts.mono, fontSize: sz.lg, color: C.accent }}>
              {config?.signing.algorithm || "—"}
            </div>
          </div>
          <div>
            <Label>Key Store</Label>
            <div style={{ fontFamily: fonts.mono, fontSize: sz.lg, color: C.text }}>
              {config?.signing.key_store || "—"}
            </div>
          </div>
          <div>
            <Label>Status</Label>
            <div style={{ fontSize: sz.base }}>
              <StatusDot status={signingSubsystem?.status || "unknown"} />
              {signingSubsystem?.status || "unknown"}
            </div>
          </div>
        </div>
      </Card>

      {/* JWKS Test Result */}
      {jwksResult && (
        <Card style={{ marginBottom: 14 }}>
          <SectionTitle>JWKS Response</SectionTitle>
          <pre style={{
            background: C.surface2,
            border: `1px solid ${C.border2}`,
            borderRadius: 4,
            padding: 12,
            fontFamily: fonts.mono,
            fontSize: sz.sm,
            color: C.textMono,
            overflow: "auto",
            maxHeight: 300,
            whiteSpace: "pre-wrap",
            wordBreak: "break-all",
          }}>
            {jwksResult}
          </pre>
          <div style={{ marginTop: 8 }}>
            <Btn secondary small onClick={() => setJwksResult(null)}>Close</Btn>
          </div>
        </Card>
      )}

      {/* JWKS Settings */}
      {config && (
        <Card>
          <SectionTitle>JWKS Settings</SectionTitle>
          <div style={{ marginBottom: 4 }}>
            <Label>Agent listing in JWKS</Label>
          </div>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 12, marginBottom: 12 }}>
            <div style={{
              width: 36, height: 20, borderRadius: 10, position: "relative",
              background: config.agents.jwks_listing ? C.success : C.border2,
              flexShrink: 0, opacity: 0.7,
            }}>
              <div style={{
                position: "absolute", top: 3, left: config.agents.jwks_listing ? 19 : 3,
                width: 14, height: 14, borderRadius: "50%", background: "#fff",
                boxShadow: "0 1px 3px rgba(0,0,0,0.4)",
              }} />
            </div>
            <div>
              <div style={{ fontSize: sz.base, color: C.text, marginBottom: 4 }}>
                {config.agents.jwks_listing
                  ? "Enabled — JWKS includes an agents array"
                  : "Disabled — JWKS exposes signing keys only"}
              </div>
              <div style={{ fontSize: sz.sm, color: C.textDim, lineHeight: 1.6 }}>
                When enabled, JWKS includes an <Mono>agents</Mono> array listing all registered agent clients.
                Enable only if your MCP servers need to validate agent identity from JWKS.
              </div>
            </div>
          </div>
          {config.agents.enabled && (
            <InfoBox color={C.purple}>
              Agents feature is enabled. {config.agents.jwks_listing ? "Agent clients appear in JWKS." : "JWKS listing is off — agents not exposed in JWKS."}
            </InfoBox>
          )}
          <div style={{ marginTop: 12, fontSize: sz.sm, color: C.textDim, fontFamily: fonts.mono }}>
            This setting is read-only in the UI — configure via server YAML.
          </div>
        </Card>
      )}
    </div>
  );
}

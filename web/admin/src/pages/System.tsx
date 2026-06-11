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
import InfoBox from "../components/InfoBox";

function subsystemStatus(status: SystemStatusResponse | null, name: string): { status: string; driver?: string } {
  const sub = status?.subsystems.find(s => s.name === name);
  return { status: sub?.status || "unknown", driver: sub?.driver };
}

export default function System() {
  const [status, setStatus] = useState<SystemStatusResponse | null>(null);
  const [config, setConfig] = useState<SystemConfigResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([getSystemStatus(), getSystemConfig()])
      .then(([s, c]) => { setStatus(s); setConfig(c); })
      .catch(err => setError(err instanceof Error ? err.message : "Failed to load system info"));
  }, []);

  const storage = subsystemStatus(status, "storage");
  const encryption = subsystemStatus(status, "encryption");

  return (
    <div style={{ padding: 28 }}>
      <div style={{ fontSize: sz.xl, fontWeight: 600, fontFamily: fonts.mono, marginBottom: 4 }}>System</div>
      <div style={{ fontSize: sz.base, color: C.textDim, marginBottom: 24 }}>
        Server health and configuration — all values sanitized
      </div>

      {error && <div style={{ marginBottom: 14 }}><InfoBox color={C.danger}>{error}</InfoBox></div>}

      {/* Health cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 24 }}>
        <Card>
          <Label>Authplane</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.lg, color: C.accent, marginBottom: 4 }}>
            v{status?.version || "—"}
          </div>
          <div style={{ fontSize: sz.base, color: C.textDim }}>
            up {status?.uptime || "—"}
          </div>
        </Card>

        <Card>
          <Label>Storage</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.base, color: C.text, marginBottom: 4 }}>
            {config?.storage.driver || storage.driver || "—"}
          </div>
          <div style={{ fontSize: sz.base }}>
            <StatusDot status={storage.status} />
            {storage.status}
          </div>
        </Card>

        <Card>
          <Label>Encryption</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.base, color: C.text, marginBottom: 4 }}>
            {config?.encryption.driver || encryption.driver || "—"}
          </div>
          <div style={{ fontSize: sz.base }}>
            <StatusDot status={encryption.status} />
            {encryption.status}
          </div>
        </Card>

        <Card>
          <Label>Rate Limiting</Label>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.base, color: C.text, marginBottom: 4 }}>
            {config?.rate_limit.enabled ? "enabled" : "disabled"}
          </div>
          <div style={{ fontSize: sz.base }}>
            <StatusDot status={config?.rate_limit.enabled ? "active" : "disabled"} />
            {config?.rate_limit.enabled ? "active" : "off"}
          </div>
        </Card>
      </div>

      {/* Server Info */}
      {config && (
        <>
          <Card style={{ marginBottom: 14 }}>
            <SectionTitle>Server Configuration</SectionTitle>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
              <div>
                <Label>Issuer</Label>
                <Mono style={{ fontSize: sz.sm, wordBreak: "break-all" }}>{config.issuer}</Mono>
              </div>
              <div>
                <Label>Signing Algorithm</Label>
                <div style={{ fontFamily: fonts.mono, fontSize: sz.md, color: C.accent }}>{config.signing.algorithm}</div>
              </div>
              <div>
                <Label>Key Store</Label>
                <Mono>{config.signing.key_store}</Mono>
              </div>
              <div>
                <Label>Storage Driver</Label>
                <Mono>{config.storage.driver}</Mono>
              </div>
              <div>
                <Label>Encryption Driver</Label>
                <Mono>{config.encryption.driver}</Mono>
              </div>
              <div>
                <Label>DCR Mode</Label>
                <Mono>{config.dcr.mode}</Mono>
              </div>
            </div>
          </Card>

          {/* Phase 3 Feature Flags */}
          <SectionTitle>Feature Flags</SectionTitle>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 14, marginBottom: 14 }}>
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Label>Client Credentials</Label>
                <Tag color={config.client_credentials.enabled ? C.success : C.textDim}>
                  {config.client_credentials.enabled ? "enabled" : "disabled"}
                </Tag>
              </div>
              <div style={{ fontSize: sz.sm, color: C.textDim }}>
                RFC 6749 §4.4 machine-to-machine tokens
              </div>
            </Card>

            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Label>DPoP</Label>
                <Tag color={config.dpop.enabled ? C.success : C.textDim}>
                  {config.dpop.enabled ? "enabled" : "disabled"}
                </Tag>
              </div>
              {config.dpop.enabled && (
                <div style={{ fontSize: sz.sm, color: C.textDim }}>
                  Nonce TTL: <Mono>{config.dpop.nonce_ttl || "default"}</Mono>
                  {" · "}
                  Require nonce: <Mono>{config.dpop.require_nonce ? "yes" : "no"}</Mono>
                </div>
              )}
            </Card>

            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Label>Token Exchange</Label>
                <Tag color={config.token_exchange.enabled ? C.success : C.textDim}>
                  {config.token_exchange.enabled ? "enabled" : "disabled"}
                </Tag>
              </div>
              {config.token_exchange.enabled && (
                <div style={{ fontSize: sz.sm, color: C.textDim }}>
                  Max chain depth: <Mono>{config.token_exchange.max_chain_depth}</Mono>
                </div>
              )}
            </Card>

            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Label>Agent Identity</Label>
                <Tag color={config.agents.enabled ? C.purple : C.textDim}>
                  {config.agents.enabled ? "enabled" : "disabled"}
                </Tag>
              </div>
              {config.agents.enabled && (
                <div style={{ fontSize: sz.sm, color: C.textDim }}>
                  JWKS listing: <Mono>{config.agents.jwks_listing ? "yes" : "no"}</Mono>
                </div>
              )}
            </Card>

            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <Label>OIDC Login</Label>
                <Tag color={config.oidc.enabled ? C.success : C.textDim}>
                  {config.oidc.enabled ? "enabled" : "disabled"}
                </Tag>
              </div>
              <div style={{ fontSize: sz.sm, color: C.textDim }}>
                External identity provider login
              </div>
            </Card>
          </div>

          <div style={{ fontSize: sz.sm, color: C.textDim, fontFamily: fonts.mono, marginTop: 8 }}>
            All configuration is read-only. Change settings via server YAML and restart.
          </div>
        </>
      )}
    </div>
  );
}

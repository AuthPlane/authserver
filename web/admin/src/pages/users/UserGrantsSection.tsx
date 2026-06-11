// UserGrantsSection.tsx — embedded grants tables for the Users detail Drawer.
//
// Pre-filtered to the selected user; uses the same `GrantsTables` component
// the full /admin/grants page renders, so the two surfaces stay in sync.
// Fires listUserGrants once when the section mounts; refetches after a
// successful revoke.

import { useState, useEffect, useCallback } from "react";
import { C, sz } from "../../tokens";
import {
  listClients, listResources, listBrokerProviders, listUserGrants,
  revokeConsentGrant, revokeBrokerGrant,
} from "../../api";
import type {
  UserView, ClientView, ResourceView, BrokerProviderView, UserGrantsView,
  ConsentGrantView, BrokerGrantView,
} from "../../api";
import Btn from "../../components/Btn";
import Modal from "../../components/Modal";
import Toast from "../../components/Toast";
import SectionTitle from "../../components/SectionTitle";
import { GrantsTables, consentRevokeCopy, brokerRevokeCopy } from "../Grants";

interface RevokeTarget {
  kind: "consent" | "broker";
  id: string;
  description: string;
}

interface Props {
  user: UserView;
}

export default function UserGrantsSection({ user }: Props) {
  const [clients, setClients] = useState<ClientView[]>([]);
  const [resources, setResources] = useState<ResourceView[]>([]);
  const [providers, setProviders] = useState<BrokerProviderView[]>([]);
  const [grants, setGrants] = useState<UserGrantsView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [toast, setToast] = useState<{ msg: string; type: "success" | "error" } | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<RevokeTarget | null>(null);

  const showToast = (msg: string, type: "success" | "error" = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [g, cs, rs, ps] = await Promise.all([
        listUserGrants(user.id),
        listClients(),
        listResources(),
        listBrokerProviders(),
      ]);
      setGrants(g);
      setClients(cs);
      setResources(rs);
      setProviders(ps);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load grants");
    } finally {
      setLoading(false);
    }
  }, [user.id]);

  useEffect(() => { load(); }, [load]);

  const performRevoke = async () => {
    if (!revokeTarget) return;
    try {
      if (revokeTarget.kind === "consent") {
        await revokeConsentGrant(revokeTarget.id);
        showToast("Consent grant revoked");
      } else {
        await revokeBrokerGrant(revokeTarget.id);
        showToast("Broker grant revoked");
      }
      setRevokeTarget(null);
      load();
    } catch (err) {
      showToast(err instanceof Error ? err.message : "Failed to revoke", "error");
    }
  };

  const handleRevokeConsent = (g: ConsentGrantView) => {
    setRevokeTarget({
      kind: "consent",
      id: g.id,
      description: consentRevokeCopy(g, clients, resources),
    });
  };
  const handleRevokeBroker = (g: BrokerGrantView) => {
    setRevokeTarget({
      kind: "broker",
      id: g.id,
      description: brokerRevokeCopy(g, providers, user),
    });
  };

  return (
    <div style={{ marginTop: 24 }}>
      <SectionTitle>Grants</SectionTitle>

      {loading && (
        <div style={{ fontSize: sz.base, color: C.textDim, padding: "8px 0" }}>Loading…</div>
      )}

      {error && (
        <div style={{ fontSize: sz.base, color: C.danger, padding: "8px 0" }}>{error}</div>
      )}

      {!loading && !error && grants && (
        <GrantsTables
          grants={grants}
          clients={clients}
          resources={resources}
          providers={providers}
          onRevokeConsent={handleRevokeConsent}
          onRevokeBroker={handleRevokeBroker}
        />
      )}

      {revokeTarget && (
        <Modal
          title={`Revoke ${revokeTarget.kind} grant?`}
          titleColor={C.danger}
          onClose={() => setRevokeTarget(null)}
        >
          <div style={{ fontSize: sz.base, color: C.textDim, lineHeight: 1.7, marginBottom: 16 }}>
            {revokeTarget.description}
          </div>
          <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
            <Btn secondary small onClick={() => setRevokeTarget(null)}>Cancel</Btn>
            <Btn danger small onClick={performRevoke}>Revoke</Btn>
          </div>
        </Modal>
      )}

      <Toast message={toast?.msg ?? null} type={toast?.type} />
    </div>
  );
}

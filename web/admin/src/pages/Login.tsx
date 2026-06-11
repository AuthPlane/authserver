import { useState, FormEvent } from "react";
import { C, fonts, sz, alpha } from "../tokens";
import { setApiKey, verifyAuth } from "../api";

interface LoginProps {
  onLogin: () => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!key.trim()) return;

    setLoading(true);
    setError("");

    // Store the key first so verifyAuth can use it.
    setApiKey(key.trim());

    try {
      const res = await verifyAuth();
      if (res.valid) {
        onLogin();
      } else {
        setError("Invalid API key");
        setApiKey("");
      }
    } catch {
      setError("Invalid API key or server unreachable");
      setApiKey("");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background: C.bg,
      }}
    >
      <div
        style={{
          width: 380,
          background: C.surface,
          border: `1px solid ${C.border}`,
          borderRadius: 10,
          padding: 32,
        }}
      >
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div
            style={{
              fontFamily: fonts.mono,
              fontSize: sz.xl,
              fontWeight: 600,
              color: C.accent,
              letterSpacing: 0.5,
              marginBottom: 4,
            }}
          >
            authplane
          </div>
          <div style={{ fontFamily: fonts.mono, fontSize: sz.sm, color: C.textDim }}>
            admin console
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label
              style={{
                display: "block",
                fontSize: sz.xs,
                fontFamily: fonts.mono,
                textTransform: "uppercase",
                letterSpacing: 1.2,
                color: C.textDim,
                marginBottom: 6,
              }}
            >
              API Key
            </label>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Enter admin API key"
              autoFocus
              style={{
                width: "100%",
                padding: "10px 14px",
                background: C.surface2,
                border: `1px solid ${error ? C.danger : C.border2}`,
                borderRadius: 6,
                color: C.text,
                fontSize: sz.base,
                fontFamily: fonts.mono,
                outline: "none",
                boxSizing: "border-box",
                transition: "border-color 0.15s",
              }}
            />
          </div>

          {error && (
            <div
              style={{
                fontSize: sz.base,
                color: C.danger,
                fontFamily: fonts.mono,
                marginBottom: 12,
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || !key.trim()}
            style={{
              width: "100%",
              padding: "10px 16px",
              fontSize: sz.base,
              fontFamily: fonts.mono,
              fontWeight: 500,
              background: alpha(C.accent, 0x20),
              color: C.accent,
              border: `1px solid ${alpha(C.accent, 0x50)}`,
              borderRadius: 6,
              cursor: loading || !key.trim() ? "not-allowed" : "pointer",
              opacity: loading || !key.trim() ? 0.5 : 1,
              transition: "all 0.15s",
              letterSpacing: 0.3,
            }}
          >
            {loading ? "Verifying…" : "Sign In"}
          </button>
        </form>

        <div
          style={{
            marginTop: 20,
            fontSize: sz.sm,
            color: C.textDim,
            textAlign: "center",
            fontFamily: fonts.mono,
            lineHeight: 1.6,
          }}
        >
          Use the API key from your server configuration.
        </div>
      </div>
    </div>
  );
}

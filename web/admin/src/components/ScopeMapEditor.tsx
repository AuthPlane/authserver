// ScopeMapEditor — reusable editor for fronting-link scope maps.
//
// A ScopeMap maps source-scope names to a non-empty list of target-scope
// names. Both sides are picked from dropdowns populated by the caller —
// no free text. If a key/value in the value prop no longer exists in the
// caller's source/target scope arrays (drift after a Resource scope was
// renamed), the row renders with a "stale" tag so the operator can see
// it and remove it explicitly.

import { C, fonts, sz, alpha } from "../tokens";
import type { ScopeMap } from "../api";
import Btn from "./Btn";
import Tag from "./Tag";

interface ScopeMapEditorProps {
  sourceScopes: string[];
  targetScopes: string[];
  value: ScopeMap;
  onChange: (next: ScopeMap) => void;
  disabled?: boolean;
}

export default function ScopeMapEditor({
  sourceScopes,
  targetScopes,
  value,
  onChange,
  disabled,
}: ScopeMapEditorProps) {
  const keys = Object.keys(value).sort();
  const usedKeys = new Set(keys);
  const availableKeys = sourceScopes.filter((s) => !usedKeys.has(s));

  const setKey = (oldKey: string, newKey: string) => {
    if (newKey === oldKey || newKey === "") return;
    const next: ScopeMap = {};
    for (const k of keys) {
      next[k === oldKey ? newKey : k] = value[k];
    }
    onChange(next);
  };

  const setValues = (key: string, vals: string[]) => {
    onChange({ ...value, [key]: vals });
  };

  const addRow = () => {
    if (availableKeys.length === 0) return;
    onChange({ ...value, [availableKeys[0]]: [] });
  };

  const removeRow = (key: string) => {
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const toggleValue = (key: string, candidate: string) => {
    const current = value[key] ?? [];
    if (current.includes(candidate)) {
      setValues(
        key,
        current.filter((v) => v !== candidate),
      );
    } else {
      setValues(key, [...current, candidate]);
    }
  };

  if (sourceScopes.length === 0 || targetScopes.length === 0) {
    return (
      <div
        style={{
          padding: "10px 12px",
          background: C.surface2,
          border: `1px dashed ${C.border2}`,
          borderRadius: 6,
          fontSize: sz.sm,
          color: C.textDim,
          fontStyle: "italic",
        }}
      >
        Select source and target to map scopes.
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(160px, 1fr) auto minmax(220px, 2fr) 28px",
          gap: 8,
          padding: "0 8px",
          fontFamily: fonts.mono,
          fontSize: sz.xs,
          color: C.textDim,
          textTransform: "uppercase",
          letterSpacing: 1,
        }}
      >
        <div>Source scope</div>
        <div></div>
        <div>Target scopes</div>
        <div></div>
      </div>
      {keys.length === 0 && (
        <div
          style={{
            padding: "10px 12px",
            background: C.surface2,
            border: `1px dashed ${C.border2}`,
            borderRadius: 6,
            fontSize: sz.sm,
            color: C.textDim,
            fontStyle: "italic",
          }}
        >
          No scope mappings yet. Click "+ Add row" to start.
        </div>
      )}

      {keys.map((key) => {
        const keyIsStale = !sourceScopes.includes(key);
        const vals = value[key] ?? [];
        const remainingTargets = targetScopes.filter((t) => !vals.includes(t));
        return (
          <div
            key={key}
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(160px, 1fr) auto minmax(220px, 2fr) 28px",
              gap: 8,
              alignItems: "start",
              padding: 8,
              background: C.surface2,
              border: `1px solid ${C.border2}`,
              borderRadius: 6,
            }}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              <select
                value={key}
                disabled={disabled}
                onChange={(e) => setKey(key, e.target.value)}
                style={{
                  width: "100%",
                  background: C.surface,
                  border: `1px solid ${C.border2}`,
                  borderRadius: 5,
                  padding: "6px 10px",
                  color: C.text,
                  fontSize: sz.base,
                  fontFamily: fonts.mono,
                }}
              >
                {/* Always show the current key first (even if stale) so the
                    select shows what's stored. */}
                <option value={key}>{key}</option>
                {availableKeys.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              {keyIsStale && (
                <Tag color={C.warn}>stale (not in source.scopes)</Tag>
              )}
            </div>

            <div
              style={{
                paddingTop: 8,
                color: C.textDim,
                fontFamily: fonts.mono,
                fontSize: sz.base,
              }}
            >
              →
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {vals.map((v) => {
                  const valStale = !targetScopes.includes(v);
                  return (
                    <span
                      key={v}
                      onClick={() => !disabled && toggleValue(key, v)}
                      style={{
                        background: alpha(
                          valStale ? C.warn : C.accent,
                          0x18,
                        ),
                        border: `1px solid ${alpha(valStale ? C.warn : C.accent, 0x40)}`,
                        color: valStale ? C.warn : C.accent,
                        borderRadius: 3,
                        padding: "2px 8px",
                        fontFamily: fonts.mono,
                        fontSize: sz.sm,
                        cursor: disabled ? "default" : "pointer",
                      }}
                      title={
                        valStale
                          ? "stale: not in target.scopes — click to remove"
                          : "click to remove"
                      }
                    >
                      {v}
                      <span style={{ color: C.textDim, marginLeft: 4 }}>
                        ✕
                      </span>
                    </span>
                  );
                })}
                {vals.length === 0 && (
                  <span
                    style={{
                      fontSize: sz.sm,
                      color: C.danger,
                      fontStyle: "italic",
                    }}
                  >
                    select at least one target scope
                  </span>
                )}
              </div>
              {remainingTargets.length > 0 && (
                <select
                  value=""
                  disabled={disabled}
                  onChange={(e) => {
                    if (e.target.value) toggleValue(key, e.target.value);
                  }}
                  style={{
                    background: C.surface,
                    border: `1px solid ${C.border2}`,
                    borderRadius: 5,
                    padding: "5px 10px",
                    color: C.text,
                    fontSize: sz.sm,
                    fontFamily: fonts.mono,
                    width: "100%",
                  }}
                >
                  <option value="">+ Add target scope…</option>
                  {remainingTargets.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <Btn danger small onClick={() => removeRow(key)} disabled={disabled}>
              ✕
            </Btn>
          </div>
        );
      })}

      <div style={{ display: "flex" }}>
        <Btn
          secondary
          small
          full
          onClick={addRow}
          disabled={disabled || availableKeys.length === 0}
        >
          + Add row
          {availableKeys.length === 0 && " (every source scope mapped)"}
        </Btn>
      </div>
    </div>
  );
}

import { ReactNode, useState } from "react";
import { C, fonts, sz } from "../tokens";
import TextInput from "./TextInput";

interface TableProps {
  headers: string[];
  rows: ReactNode[][];
  onRowClick?: (index: number) => void;
  searchable?: boolean;
  searchPlaceholder?: string;
  filterFn?: (row: ReactNode[], term: string) => boolean;
}

export default function Table({ headers, rows, onRowClick, searchable, searchPlaceholder, filterFn }: TableProps) {
  const [search, setSearch] = useState("");

  const filtered = searchable && search && filterFn
    ? rows.filter((row) => filterFn(row, search))
    : rows;

  return (
    <div>
      {searchable && (
        <div style={{ marginBottom: 12 }}>
          <TextInput
            placeholder={searchPlaceholder || "Search…"}
            value={search}
            onChange={setSearch}
            style={{ width: 280 }}
          />
        </div>
      )}
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: sz.base }}>
        <thead>
          <tr>
            {headers.map((h) => (
              <th
                key={h}
                style={{
                  textAlign: "left",
                  padding: "8px 12px",
                  color: C.textDim,
                  fontFamily: fonts.mono,
                  fontSize: sz.xs,
                  textTransform: "uppercase",
                  letterSpacing: 1.2,
                  borderBottom: `1px solid ${C.border}`,
                  fontWeight: 400,
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filtered.map((row, i) => (
            <tr
              key={i}
              onClick={() => onRowClick?.(i)}
              style={{
                cursor: onRowClick ? "pointer" : "default",
                borderBottom: `1px solid ${C.border}`,
                transition: "background 0.1s",
              }}
              onMouseEnter={(e) => {
                if (onRowClick) e.currentTarget.style.background = C.surface2;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "transparent";
              }}
            >
              {row.map((cell, j) => (
                <td key={j} style={{ padding: "10px 12px", verticalAlign: "middle" }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

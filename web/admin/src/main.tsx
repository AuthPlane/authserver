import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { initPreferences } from "./tokens";
import App from "./App";

// Ensure CSS variables are set (index.html script handles flash prevention,
// but this ensures tokens.ts state is in sync with localStorage).
initPreferences();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);

import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";
import { WorkspaceContextProvider } from "./app/WorkspaceContext";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WorkspaceContextProvider><App /></WorkspaceContextProvider>
  </React.StrictMode>
);

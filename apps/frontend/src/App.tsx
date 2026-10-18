import { AppShell } from "./app/AppShell";
import { WorkspaceProvider } from "./app/WorkspaceProvider";
export function App(){return <WorkspaceProvider><AppShell/></WorkspaceProvider>;}

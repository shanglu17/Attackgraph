import { createContext, useContext, useMemo, useState, type PropsWithChildren } from "react";

export interface WorkspaceScope {
  projectId: string;
  revisionId: string;
  profileId: string;
  baselineId: string;
  apiKey: string;
}

interface WorkspaceContextValue extends WorkspaceScope {
  update: (values: Partial<WorkspaceScope>) => void;
}

const storageKey = "astra.workspace-scope.v1";

function initialScope(): WorkspaceScope {
  try {
    const stored = JSON.parse(sessionStorage.getItem(storageKey) ?? "{}") as Partial<WorkspaceScope>;
    return { projectId: stored.projectId ?? "", revisionId: stored.revisionId ?? "", profileId: stored.profileId ?? "", baselineId: stored.baselineId ?? "", apiKey: "" };
  } catch {
    return { projectId: "", revisionId: "", profileId: "", baselineId: "", apiKey: "" };
  }
}

const WorkspaceContext = createContext<WorkspaceContextValue | undefined>(undefined);

export function WorkspaceContextProvider({ children }: PropsWithChildren) {
  const [scope, setScope] = useState<WorkspaceScope>(initialScope);
  const value = useMemo<WorkspaceContextValue>(() => ({
    ...scope,
    update(values) {
      setScope((current) => {
        const next = { ...current, ...values };
        const { apiKey: _apiKey, ...persisted } = next;
        sessionStorage.setItem(storageKey, JSON.stringify(persisted));
        return next;
      });
    },
  }), [scope]);
  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspaceContext(): WorkspaceContextValue {
  const value = useContext(WorkspaceContext);
  if (!value) throw new Error("useWorkspaceContext must be used inside WorkspaceContextProvider");
  return value;
}

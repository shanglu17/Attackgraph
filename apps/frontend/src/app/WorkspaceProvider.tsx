import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type PropsWithChildren,
} from "react";
import type {
  EditPreview,
  InventoryPreviewResult,
  InventoryPreview,
  SavedAnalysisCommand,
  StoredAnalysisRun,
  WorkbenchSnapshot,
  WorkspaceChoice,
} from "@attackgraph/contracts";
import { workbenchApi } from "../api";
import { useWorkspaceContext } from "./WorkspaceContext";
import type { Draft, Workspace } from "../shared/model/workbench";
import type { ParsedFhaDocument } from "../fhaDocument";

export interface WorkspaceSession {
  inventoryAircraftModel:string;
  documentPreview:ParsedFhaDocument|null;
  snapshot: WorkbenchSnapshot | null;
  runs: StoredAnalysisRun[];
  draft: Draft | null;
  conflict: boolean;
  parameters: SavedAnalysisCommand["parameters"];
  selectedAsset: string;
  selectedPath: string;
  selectedRun: string;
  editKind: "assets" | "data_flows" | "draft_threats";
  editId: string;
  jsonText: string;
  newEntityId: string;
  importRequest: InventoryPreview | null;
  importPreview: InventoryPreviewResult | null;
  editPreview: EditPreview | null;
  busy: boolean;
  error: string;
  message: string;
}
function initial(key?: string): WorkspaceSession {
  const value: WorkspaceSession = {
    inventoryAircraftModel:"",
    documentPreview:null,
    snapshot: null,
    runs: [],
    draft: null,
    conflict: false,
    parameters: { max_hops: 3, dps_hop_decay: 0.95 },
    selectedAsset: "",
    selectedPath: "",
    selectedRun: "",
    editKind: "assets",
    editId: "",
    jsonText: "",
    newEntityId: "",
    importRequest: null,
    importPreview: null,
    editPreview: null,
    busy: false,
    error: "",
    message: "选择项目与修订，然后导入系统资产清单。",
  };
  if (key)
    try {
      const saved = JSON.parse(
        sessionStorage.getItem("astra.production.ui:" + key) ?? "{}",
      );
      for (const field of [
        "selectedAsset",
        "selectedPath",
        "selectedRun",
        "editId",
      ] as const)
        if (typeof saved[field] === "string") value[field] = saved[field];
      if (["assets", "data_flows", "draft_threats"].includes(saved.editKind))
        value.editKind = saved.editKind;
      if (
        Number.isInteger(saved.parameters?.max_hops) &&
        saved.parameters.max_hops >= 1 &&
        saved.parameters.max_hops <= 8 &&
        saved.parameters.dps_hop_decay >= 0.8 &&
        saved.parameters.dps_hop_decay <= 1
      )
        value.parameters = {
          max_hops: saved.parameters.max_hops,
          dps_hop_decay: saved.parameters.dps_hop_decay,
        };
    } catch {
      /* invalid UI preferences do not restore model data */
    }
  return value;
}
interface Value {
  state: WorkspaceSession;
  workspace: Workspace;
  navigate: (w: Workspace) => void;
  choices: WorkspaceChoice[];
  refreshChoices: () => Promise<void>;
  patch: (p: Partial<WorkspaceSession>) => void;
  perform: (action: () => Promise<void>) => Promise<void>;
  refresh: () => Promise<void>;
  beginDraft: () => void;
  updateDraft: (draft: Draft | null) => void;
  envelope: (
    operation?: string,
    payload?: unknown,
  ) => {
    project_id: string;
    revision_id: string;
    expected_revision_version: number;
    actor: string;
    command_id: string;
  };
}
const Context = createContext<Value | null>(null);
const draftKey = (key: string) => "astra.production.draft.v1:" + key;
export function WorkspaceProvider({ children }: PropsWithChildren) {
  const scope = useWorkspaceContext();
  const key = scope.projectId + ":" + scope.revisionId;
  const [sessions, setSessions] = useState<Record<string, WorkspaceSession>>(
    {},
  );
  const [workspace, setWorkspace] = useState<Workspace>(() => {
    try {
      const saved = sessionStorage.getItem("astra.production.workspace");
      return ["imports", "analysis", "changes", "reports"].includes(saved ?? "")
        ? (saved as Workspace)
        : "imports";
    } catch {
      return "imports";
    }
  });
  const [choices, setChoices] = useState<WorkspaceChoice[]>([]);
  const reads = useRef<Record<string, number>>({});
  const running = useRef(new Set<string>());
  const commands = useRef(new Map<string, string>());
  const state = sessions[key] ?? initial(key);
  const patch = (p: Partial<WorkspaceSession>) =>
    setSessions((all) => ({
      ...all,
      [key]: { ...(all[key] ?? initial(key)), ...p },
    }));
  useEffect(() => {
    try {
      sessionStorage.setItem(
        "astra.production.ui:" + key,
        JSON.stringify({
          parameters: state.parameters,
          selectedAsset: state.selectedAsset,
          selectedPath: state.selectedPath,
          selectedRun: state.selectedRun,
          editKind: state.editKind,
          editId: state.editId,
        }),
      );
    } catch {
      /* UI selection remains available in memory */
    }
  }, [
    key,
    state.parameters,
    state.selectedAsset,
    state.selectedPath,
    state.selectedRun,
    state.editKind,
    state.editId,
  ]);
  const refreshChoices = async () => {
    const response = await workbenchApi.listWorkspaces();
    setChoices(response.workspaces);
  };
  const navigate = (w: Workspace) => {
    setWorkspace(w);
    try {
      sessionStorage.setItem("astra.production.workspace", w);
    } catch {
      /* UI state remains in memory */
    }
  };
  async function refresh() {
    if (!scope.projectId || !scope.revisionId) return;
    const ticket = (reads.current[key] ?? 0) + 1;
    reads.current[key] = ticket;
    const [snapshot, result] = await Promise.all([
      workbenchApi.read({
        project_id: scope.projectId,
        revision_id: scope.revisionId,
      }),
      workbenchApi.runs({
        project_id: scope.projectId,
        revision_id: scope.revisionId,
      }),
    ]);
    if (ticket !== reads.current[key]) return;
    let recovered: Draft | null = null;
    try {
      const raw = localStorage.getItem(draftKey(key));
      if (raw) {
        const { restoreDraft } = await import(
          "../shared/model/draftPersistence"
        );
        recovered = restoreDraft(
          JSON.parse(raw),
          scope.projectId,
          scope.revisionId,
        );
      }
    } catch {
      /* corrupt local draft does not replace the server model */
    }
    if (ticket !== reads.current[key]) return;
    setSessions((all) => {
      const previous = all[key] ?? initial(key);
      let draft = previous.draft;
      if (!draft) draft = recovered;
      if (
        draft &&
        (draft.project_id !== scope.projectId ||
          draft.revision_id !== scope.revisionId)
      )
        draft = null;
      return {
        ...all,
        [key]: {
          ...previous,
          snapshot,
          runs: result.runs.filter(
            (r) => r.method.method_id === "dfs-dps-attack-path",
          ),
          draft,
          conflict:
            !!draft && draft.base_version !== snapshot.model.revision_version,
        },
      };
    });
  }
  async function perform(action: () => Promise<void>) {
    if (running.current.has(key)) return;
    running.current.add(key);
    patch({ busy: true, error: "" });
    try {
      await action();
    } catch (cause) {
      const e = cause as {
        message?: string;
        sheet?: string;
        row?: number;
        field?: string;
        status?: number;
      };
      if (e.status === 409) {
        try {
          await refresh();
        } catch {
          /* keep original conflict visible */
        }
      }
      patch({
        error: [
          e.sheet,
          e.row ? `Excel 第 ${e.row} 行` : "",
          e.field,
          e.message ?? "操作失败，请重试",
        ]
          .filter(Boolean)
          .join(" · "),
      });
    } finally {
      running.current.delete(key);
      patch({ busy: false });
    }
  }
  useEffect(() => {
    void perform(async () => {
      await refreshChoices();
      await refresh();
    });
  }, [key]);
  function updateDraft(draft: Draft | null) {
    patch({
      draft,
      editPreview: null,
      conflict:
        !!draft &&
        draft.base_version !== state.snapshot?.model.revision_version,
    });
    try {
      if (draft) localStorage.setItem(draftKey(key), JSON.stringify(draft));
      else localStorage.removeItem(draftKey(key));
    } catch {
      patch({ error: "草稿无法写入本地存储，刷新前请先保存到服务端。" });
    }
  }
  function beginDraft() {
    if (state.snapshot && !state.draft)
      updateDraft({
        project_id: scope.projectId,
        revision_id: scope.revisionId,
        base_version: state.snapshot.model.revision_version,
        entities: structuredClone(state.snapshot.model.entities),
        configuration: structuredClone(state.snapshot.configuration),
      });
  }
  function envelope(operation = "command", payload?: unknown) {
    if (!state.snapshot) throw new Error("尚未加载修订");
    const fingerprint = JSON.stringify([
      key,
      state.snapshot.model.revision_version,
      operation,
      payload,
    ]);
    if (!commands.current.has(fingerprint))
      commands.current.set(fingerprint, crypto.randomUUID());
    return {
      project_id: scope.projectId,
      revision_id: scope.revisionId,
      expected_revision_version: state.snapshot.model.revision_version,
      actor: "workbench-user",
      command_id: commands.current.get(fingerprint)!,
    };
  }
  return (
    <Context.Provider
      value={{
        state,
        workspace,
        navigate,
        choices,
        refreshChoices,
        patch,
        perform,
        refresh,
        beginDraft,
        updateDraft,
        envelope,
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function useWorkbench() {
  const c = useContext(Context);
  if (!c) throw new Error("WorkspaceProvider missing");
  return c;
}

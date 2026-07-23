import { useEffect, useMemo, useState } from "react";
import { commitChangeSet, validateChangeSet } from "../../api";
import type { ChangeSet, GraphChangeSet, GraphData } from "../../types";
import {
  ENTITY_FIELDS,
  ENTITY_ID_FIELDS,
  ENTITY_LABELS,
  ENTITY_TYPES,
  createEntityTemplate,
  createFormState,
  describeEntity,
  emptyChangeSet,
  formStateToObject,
  getDraftBucket,
  getEntityId,
  getEntityItems,
  hasDraftChanges,
  parseEditorValue,
  stringifyEntity,
  upsertEntity,
  type DraftOperation,
  type EditableEntity,
  type EditorMode,
  type EntityType,
  type FormState
} from "./changeSetModel";

interface ChangeSetStudioProps {
  graph: GraphData | null;
  busy: boolean;
  onBusyChange: (busy: boolean) => void;
  onMessageChange: (message: string) => void;
  onReloadGraph: () => Promise<void>;
}

export function ChangeSetStudio({ graph, busy, onBusyChange, onMessageChange, onReloadGraph }: ChangeSetStudioProps) {
  const [draft, setDraft] = useState<GraphChangeSet | null>(() => graph ? emptyChangeSet(graph.graph_version) : null);
  const [editorMode, setEditorMode] = useState<EditorMode>("form");
  const [editorEntityType, setEditorEntityType] = useState<EntityType>("asset_nodes");
  const [editorOperation, setEditorOperation] = useState<DraftOperation>("add");
  const [selectedExistingId, setSelectedExistingId] = useState("");
  const [editorValue, setEditorValue] = useState("");
  const [formState, setFormState] = useState<FormState>(createFormState("asset_nodes", null));

  const existingItems = useMemo(() => getEntityItems(graph, editorEntityType), [graph, editorEntityType]);
  const selectedExistingItem = useMemo(
    () => existingItems.find((item) => getEntityId(editorEntityType, item) === selectedExistingId) ?? null,
    [editorEntityType, existingItems, selectedExistingId]
  );
  const draftSummary = useMemo(
    () => draft ? ENTITY_TYPES.map((entityType) => {
      const bucket = getDraftBucket(draft, entityType);
      return { entityType, add: bucket.add.length, update: bucket.update.length, delete: bucket.delete.length };
    }) : [],
    [draft]
  );
  const draftCount = draftSummary.reduce((total, item) => total + item.add + item.update + item.delete, 0);

  useEffect(() => {
    setDraft(graph ? emptyChangeSet(graph.graph_version) : null);
  }, [graph?.graph_version]);

  useEffect(() => {
    if (!graph) {
      setSelectedExistingId("");
      setEditorValue("");
      setFormState(createFormState(editorEntityType, null));
      return;
    }

    if (editorOperation === "add") {
      const template = createEntityTemplate(editorEntityType, graph);
      setSelectedExistingId("");
      setEditorValue(stringifyEntity(template));
      setFormState(createFormState(editorEntityType, template));
      return;
    }

    const candidateIds = existingItems.map((item) => getEntityId(editorEntityType, item)).filter(Boolean);
    const nextSelectedId = candidateIds.includes(selectedExistingId) ? selectedExistingId : (candidateIds[0] ?? "");
    if (nextSelectedId !== selectedExistingId) {
      setSelectedExistingId(nextSelectedId);
      return;
    }

    setEditorValue(editorOperation === "update" ? stringifyEntity(selectedExistingItem) : "");
    setFormState(createFormState(editorEntityType, selectedExistingItem));
  }, [editorEntityType, editorOperation, existingItems, graph, selectedExistingId, selectedExistingItem]);

  function handleResetDraft() {
    if (!graph) return;
    setDraft(emptyChangeSet(graph.graph_version));
    onMessageChange(`Draft cleared for graph version ${graph.graph_version}`);
  }

  async function handleReloadLatest() {
    await onReloadGraph();
    if (graph) setDraft(emptyChangeSet(graph.graph_version));
  }

  function handleLoadEditorSource() {
    if (!graph) return;
    const sourceItem = editorOperation === "add" ? createEntityTemplate(editorEntityType, graph) : selectedExistingItem;
    setEditorValue(stringifyEntity(sourceItem));
    setFormState(createFormState(editorEntityType, sourceItem));
  }

  function handleEditorModeChange(nextMode: EditorMode) {
    if (nextMode === editorMode) return;
    if (nextMode === "json") {
      setEditorValue(JSON.stringify(formStateToObject(editorEntityType, formState), null, 2));
    } else {
      try {
        setFormState(createFormState(editorEntityType, parseEditorValue(editorValue) as unknown as EditableEntity));
      } catch {
        const sourceItem = graph
          ? editorOperation === "add" ? createEntityTemplate(editorEntityType, graph) : selectedExistingItem
          : null;
        setFormState(createFormState(editorEntityType, sourceItem));
      }
    }
    setEditorMode(nextMode);
  }

  function handleStageChange() {
    if (!graph || !draft) return;

    if (editorOperation === "delete") {
      const deleteId = selectedExistingId.trim();
      if (!deleteId) {
        onMessageChange(`Select one ${ENTITY_LABELS[editorEntityType]} to delete`);
        return;
      }
      const existsInGraph = existingItems.some((item) => getEntityId(editorEntityType, item) === deleteId);
      setDraft((current) => {
        if (!current) return current;
        const bucket = getDraftBucket(current, editorEntityType);
        const nextBucket: ChangeSet<EditableEntity> = {
          add: bucket.add.filter((item) => getEntityId(editorEntityType, item) !== deleteId),
          update: bucket.update.filter((item) => getEntityId(editorEntityType, item) !== deleteId),
          delete: existsInGraph ? Array.from(new Set([...bucket.delete, deleteId])) : bucket.delete.filter((id) => id !== deleteId)
        };
        return { ...current, [editorEntityType]: nextBucket };
      });
      onMessageChange(`Queued delete for ${ENTITY_LABELS[editorEntityType]} ${deleteId}`);
      return;
    }

    try {
      const parsedEntity = editorMode === "form"
        ? formStateToObject(editorEntityType, formState) as unknown as EditableEntity
        : parseEditorValue(editorValue) as unknown as EditableEntity;
      const nextId = getEntityId(editorEntityType, parsedEntity);
      if (!nextId) throw new Error(`JSON must include ${ENTITY_ID_FIELDS[editorEntityType]}`);

      setDraft((current) => {
        if (!current) return current;
        const bucket = getDraftBucket(current, editorEntityType);
        const isAlreadyNew = bucket.add.some((item) => getEntityId(editorEntityType, item) === nextId);
        const shouldStoreAsAdd = editorOperation === "add" || isAlreadyNew;
        const nextBucket: ChangeSet<EditableEntity> = {
          add: shouldStoreAsAdd ? upsertEntity(bucket.add, editorEntityType, parsedEntity) : bucket.add.filter((item) => getEntityId(editorEntityType, item) !== nextId),
          update: shouldStoreAsAdd ? bucket.update.filter((item) => getEntityId(editorEntityType, item) !== nextId) : upsertEntity(bucket.update, editorEntityType, parsedEntity),
          delete: bucket.delete.filter((id) => id !== nextId)
        };
        return { ...current, [editorEntityType]: nextBucket };
      });
      onMessageChange(`Queued ${editorOperation} for ${ENTITY_LABELS[editorEntityType]} ${nextId}`);
    } catch (error) {
      onMessageChange(error instanceof Error ? error.message : "Invalid editor payload");
    }
  }

  function handleRemoveDraftEntry(entityType: EntityType, operation: DraftOperation, id: string) {
    setDraft((current) => {
      if (!current) return current;
      const bucket = getDraftBucket(current, entityType);
      const nextBucket: ChangeSet<EditableEntity> = {
        add: operation === "add" ? bucket.add.filter((item) => getEntityId(entityType, item) !== id) : bucket.add,
        update: operation === "update" ? bucket.update.filter((item) => getEntityId(entityType, item) !== id) : bucket.update,
        delete: operation === "delete" ? bucket.delete.filter((item) => item !== id) : bucket.delete
      };
      return { ...current, [entityType]: nextBucket };
    });
  }

  async function handleValidate() {
    if (!draft) return;
    try {
      onBusyChange(true);
      const result = await validateChangeSet(draft);
      onMessageChange(result.valid ? "Draft validation passed" : `Draft validation failed: ${result.errors.join("; ")}`);
    } catch (error) {
      onMessageChange(error instanceof Error ? error.message : "Failed to validate draft");
    } finally {
      onBusyChange(false);
    }
  }

  async function handleCommit() {
    if (!draft) return;
    if (!hasDraftChanges(draft)) {
      onMessageChange("Draft is empty. Queue at least one change before commit.");
      return;
    }
    try {
      onBusyChange(true);
      const result = await commitChangeSet(draft);
      if (!result.committed) {
        onMessageChange(`Commit failed: ${(result.errors ?? []).join("; ")}`);
        return;
      }
      await onReloadGraph();
      onMessageChange(`Commit succeeded: ${result.commit_id}, version ${result.new_version}`);
    } catch (error) {
      onMessageChange(error instanceof Error ? error.message : "Failed to commit draft");
    } finally {
      onBusyChange(false);
    }
  }

  return (
    <section className="panel bottom changeset-studio" aria-labelledby="changeset-title">
      <div className="changeset-header">
        <div>
          <h2 id="changeset-title" className="section-title">变更工作台</h2>
          <p>选择对象并编辑，将多项修改集中校验后一次提交。</p>
        </div>
        <div className="changeset-meta" aria-label="草稿摘要">
          <span className="pill">版本 {draft?.graph_version ?? "-"}</span>
          <span className="pill">待提交 {draftCount}</span>
          {draftSummary.filter((item) => item.add + item.update + item.delete > 0).map((item) => (
            <span key={item.entityType} className="pill">
              {ENTITY_LABELS[item.entityType]} +{item.add} / ~{item.update} / -{item.delete}
            </span>
          ))}
        </div>
      </div>

      <div className="changeset-actions" aria-label="草稿操作">
        <button className="button" onClick={() => void handleValidate()} disabled={!draft || busy}>校验草稿</button>
        <button className="button primary" onClick={() => void handleCommit()} disabled={!draft || busy || !hasDraftChanges(draft)}>提交全部变更</button>
        <button className="button" onClick={handleResetDraft} disabled={!draft || busy || !hasDraftChanges(draft)}>清空草稿</button>
        <button className="button" onClick={() => void handleReloadLatest()} disabled={busy}>重新载入图谱</button>
      </div>

      <div className="changeset-grid">
        <section className="editor-shell" aria-labelledby="entity-editor-title">
          <div className="subsection-heading">
            <div>
              <h3 id="entity-editor-title">实体编辑</h3>
              <p>先选择实体和操作，再填写必要字段。</p>
            </div>
          </div>

          <div className="changeset-control-grid">
            <label className="field-stack">
              <span className="field-label">实体类型</span>
              <select className="input-field" value={editorEntityType} onChange={(event) => setEditorEntityType(event.target.value as EntityType)} disabled={!graph}>
                {ENTITY_TYPES.map((entityType) => <option key={entityType} value={entityType}>{ENTITY_LABELS[entityType]}</option>)}
              </select>
            </label>
            <label className="field-stack">
              <span className="field-label">操作</span>
              <select className="input-field" value={editorOperation} onChange={(event) => setEditorOperation(event.target.value as DraftOperation)} disabled={!graph}>
                <option value="add">新增</option>
                <option value="update">更新</option>
                <option value="delete">删除</option>
              </select>
            </label>
            {editorOperation !== "add" ? (
              <label className="field-stack changeset-current-item">
                <span className="field-label">现有 {ENTITY_LABELS[editorEntityType]}</span>
                <select className="input-field" value={selectedExistingId} onChange={(event) => setSelectedExistingId(event.target.value)} disabled={!graph || existingItems.length === 0}>
                  {existingItems.length === 0 ? <option value="">暂无可选项</option> : null}
                  {existingItems.map((item) => {
                    const id = getEntityId(editorEntityType, item);
                    return <option key={id} value={id}>{id}</option>;
                  })}
                </select>
              </label>
            ) : <div className="changeset-control-hint">新增操作会预填一个可编辑模板。</div>}
          </div>

          {editorOperation === "delete" ? (
            <div className="delete-preview">
              <div>
                <strong>待删除对象</strong>
                <span>{selectedExistingId || "请先选择现有对象"}</span>
              </div>
              <button className="button danger-subtle" onClick={handleStageChange} disabled={!draft || busy || !selectedExistingId}>加入删除队列</button>
            </div>
          ) : (
            <div className="editor-body">
              <div className="editor-toolbar">
                <div className="mode-toggle" role="tablist" aria-label="编辑模式">
                  <button className={`mode-toggle-button ${editorMode === "form" ? "active" : ""}`} onClick={() => handleEditorModeChange("form")} type="button" role="tab" aria-selected={editorMode === "form"} disabled={!graph}>表单</button>
                  <button className={`mode-toggle-button ${editorMode === "json" ? "active" : ""}`} onClick={() => handleEditorModeChange("json")} type="button" role="tab" aria-selected={editorMode === "json"} disabled={!graph}>JSON</button>
                </div>
                <div className="editor-actions">
                  <button className="button" onClick={handleLoadEditorSource} disabled={!graph}>{editorOperation === "add" ? "恢复模板" : "重新载入对象"}</button>
                  <button className="button primary" onClick={handleStageChange} disabled={!draft || busy || !graph}>加入{editorOperation === "add" ? "新增" : "更新"}队列</button>
                </div>
              </div>

              {editorMode === "form" ? (
                <div className="form-grid changeset-form-grid">
                  {ENTITY_FIELDS[editorEntityType].map((field) => (
                    <label key={field.key} className={`field-stack ${field.kind === "textarea" ? "field-span-2" : ""}`}>
                      <span className="field-label">{field.label}{field.required ? " *" : ""}</span>
                      {field.kind === "textarea" ? (
                        <textarea className="input-field form-textarea" value={formState[field.key] ?? ""} onChange={(event) => setFormState((current) => ({ ...current, [field.key]: event.target.value }))} placeholder={field.placeholder} spellCheck={false} disabled={!graph} />
                      ) : field.kind === "select" ? (
                        <select className="input-field" value={formState[field.key] ?? ""} onChange={(event) => setFormState((current) => ({ ...current, [field.key]: event.target.value }))} disabled={!graph}>
                          <option value="">{field.required ? "请选择" : "可选"}</option>
                          {(field.options ?? []).map((option) => <option key={option} value={option}>{option}</option>)}
                        </select>
                      ) : (
                        <input className="input-field" type={field.kind === "number" ? "number" : "text"} value={formState[field.key] ?? ""} onChange={(event) => setFormState((current) => ({ ...current, [field.key]: event.target.value }))} placeholder={field.placeholder} spellCheck={false} disabled={!graph} />
                      )}
                    </label>
                  ))}
                </div>
              ) : (
                <label className="field-stack">
                  <span className="field-label">实体 JSON</span>
                  <textarea className="input-field draft-json" value={editorValue} onChange={(event) => setEditorValue(event.target.value)} spellCheck={false} disabled={!graph} />
                </label>
              )}
            </div>
          )}
        </section>

        <section className="queue-shell" aria-labelledby="change-queue-title">
          <div className="subsection-heading queue-heading">
            <div>
              <h3 id="change-queue-title">变更队列</h3>
              <p>{draftCount > 0 ? `已有 ${draftCount} 项待提交变更。` : "加入变更后可在这里统一检查。"}</p>
            </div>
            <span className="queue-count">{draftCount}</span>
          </div>

          <div className="stage-list compact-stage-list">
            {draft && hasDraftChanges(draft) ? ENTITY_TYPES.map((entityType) => {
              const bucket = getDraftBucket(draft, entityType);
              if (bucket.add.length + bucket.update.length + bucket.delete.length === 0) return null;
              return (
                <div key={entityType} className="stage-group">
                  <div className="stage-group-header">
                    <strong>{ENTITY_LABELS[entityType]}</strong>
                    <span className="pill">+{bucket.add.length} / ~{bucket.update.length} / -{bucket.delete.length}</span>
                  </div>
                  {bucket.add.map((item) => <QueueEntry key={`add-${getEntityId(entityType, item)}`} operation="add" id={getEntityId(entityType, item)} description={describeEntity(entityType, item)} onRemove={() => handleRemoveDraftEntry(entityType, "add", getEntityId(entityType, item))} />)}
                  {bucket.update.map((item) => <QueueEntry key={`update-${getEntityId(entityType, item)}`} operation="update" id={getEntityId(entityType, item)} description={describeEntity(entityType, item)} onRemove={() => handleRemoveDraftEntry(entityType, "update", getEntityId(entityType, item))} />)}
                  {bucket.delete.map((id) => <QueueEntry key={`delete-${id}`} operation="delete" id={id} onRemove={() => handleRemoveDraftEntry(entityType, "delete", id)} />)}
                </div>
              );
            }) : (
              <div className="queue-empty-state">
                <strong>草稿为空</strong>
                <span>从左侧编辑器添加第一项变更。</span>
              </div>
            )}
          </div>

          <details className="json-disclosure">
            <summary>查看草稿 JSON</summary>
            <pre>{draft ? JSON.stringify(draft, null, 2) : "请先载入图谱。"}</pre>
          </details>
        </section>
      </div>
    </section>
  );
}

interface QueueEntryProps {
  operation: DraftOperation;
  id: string;
  description?: string;
  onRemove: () => void;
}

function QueueEntry({ operation, id, description, onRemove }: QueueEntryProps) {
  return (
    <div className="stage-entry">
      <div className="stage-entry-main">
        <span className="tag">{operation}</span>
        <strong>{id}</strong>
        {description ? <span>{description}</span> : null}
      </div>
      <button className="button compact-button" onClick={onRemove}>移除</button>
    </div>
  );
}

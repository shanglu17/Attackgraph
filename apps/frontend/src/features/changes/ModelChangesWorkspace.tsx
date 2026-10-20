import type { EditCommand, ThreatParameters } from "@attackgraph/contracts";
import { useWorkbench } from "../../app/WorkspaceProvider";
import { workbenchApi } from "../../api";
import { EntityForm, type EditableKind } from "./EntityForm";
import { FieldComparison } from "./FieldComparison";
export default function ModelChangesWorkspace() {
  const {
    state,
    patch,
    perform,
    envelope,
    refresh,
    beginDraft,
    updateDraft,
    navigate,
  } = useWorkbench();
  const kind = state.editKind,
    selected = state.editId,
    newId = state.newEntityId,
    json = state.jsonText;
  const setKind = (editKind: EditableKind) => patch({ editKind });
  const setSelected = (editId: string) => patch({ editId });
  const setNewId = (newEntityId: string) => patch({ newEntityId });
  const setJson = (jsonText: string) => patch({ jsonText });
  const snapshot = state.snapshot;
  const draft = state.draft;
  if (!snapshot?.model.entities.assets.length)
    return (
      <section className="panel">
        <h2>变更管理</h2>
        <p>请先导入模型并保存。</p>
        <button className="button" onClick={() => navigate("imports")}>
          准备清单
        </button>
      </section>
    );
  const readonly = snapshot.status !== "Draft";
  const rows = draft?.entities[kind] ?? snapshot.model.entities[kind];
  const item = rows.find((r) => r.business_id === selected) ?? rows[0];
  function edit(field: string, value: unknown) {
    if (!draft || !item) return;
    const next = structuredClone(draft);
    Object.assign(
      next.entities[kind].find((r) => r.business_id === item.business_id)!,
      { [field]: value },
    );
    updateDraft(next);
  }
  const request = (): EditCommand => ({
    ...envelope("edit", draft),
    expected_revision_version: draft!.base_version,
    contract_version: "model-edit.v1",
    entities: draft!.entities,
    configuration: draft!.configuration,
  });
  const references =
    item && draft
      ? Object.entries(draft.entities).flatMap(([collection, list]) =>
          list
            .filter(
              (r) =>
                r.business_id !== item.business_id &&
                JSON.stringify(r).includes(`"${item.business_id}"`),
            )
            .map((r) => `${collection}:${r.business_id}`),
        )
      : [];
  return (
    <section className="panel">
      <span className="tag">03 / 编辑与保存</span>
      <h2>变更管理</h2>
      <p>编辑 → 查看差异 → 服务端校验 → 保存 → 重新分析</p>
      {readonly && (
        <p className="workbench-warning">当前项目已归档或修订已冻结，只能查看。</p>
      )}
      {!draft ? (
        <button
          className="button primary"
          disabled={readonly || state.busy}
          onClick={beginDraft}
        >
          开始编辑
        </button>
      ) : (
        <>
          <p>
            草稿基础版本 v{draft.base_version} · 当前服务端版本 v
            {snapshot.model.revision_version}。未保存草稿不参与正式分析。
          </p>
          <div className="toolbar wrap">
            <label className="field-stack">
              编辑类型
              <select
                aria-label="编辑类型"
                className="input-field"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value as EditableKind);
                  setSelected("");
                }}
              >
                <option value="assets">资产</option>
                <option value="data_flows">连接 / 数据流</option>
                <option value="draft_threats">威胁与参数</option>
              </select>
            </label>
            <label className="field-stack">
              对象
              <select
                aria-label="对象"
                className="input-field"
                value={item?.business_id ?? ""}
                onChange={(e) => setSelected(e.target.value)}
              >
                {rows.map((r) => (
                  <option key={r.business_id} value={r.business_id}>
                    {r.business_id} · {r.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {item && (
            <>
              <EntityForm
                kind={kind}
                record={item}
                configuration={draft.configuration}
                disabled={state.busy || readonly}
                onChange={edit}
                onThreat={(field, value) => {
                  const next = structuredClone(draft);
                  const previous = next.configuration.threat_overrides[
                    item.business_id
                  ] ?? {
                    entry_likelihood_level: "Medium",
                    attack_complexity_level: "Medium",
                    threat_source: "external",
                    stride_category: "Tampering",
                    attack_vector: "Network",
                  };
                  next.configuration.threat_overrides[item.business_id] = {
                    ...previous,
                    [field]: value,
                  } as ThreatParameters;
                  updateDraft(next);
                }}
              />
              <p>
                被引用情况：
                {references.join("、") ||
                  "核心实体未发现引用；保存时仍执行服务端检查。"}
              </p>
              <button
                className="button"
                disabled={readonly || state.busy}
                onClick={() => {
                  const next = structuredClone(draft);
                  next.entities[kind] = next.entities[kind].filter(
                    (r) => r.business_id !== item.business_id,
                  ) as never;
                  if (kind === "draft_threats")
                    delete next.configuration.threat_overrides[
                      item.business_id
                    ];
                  updateDraft(next);
                }}
              >
                从草稿删除此对象
              </button>
              <p>删除不会自动移除关联对象；悬空引用会阻止保存。</p>
            </>
          )}
          <details>
            <summary>新增对象</summary>
            <label className="field-stack">
              新对象编号
              <input
                className="input-field"
                value={newId}
                onChange={(e) => setNewId(e.target.value)}
              />
            </label>
            <button
              className="button"
              disabled={
                readonly ||
                state.busy ||
                !newId.trim() ||
                rows.some((r) => r.business_id === newId)
              }
              onClick={() => {
                const next = structuredClone(draft);
                const common = {
                  business_id: newId.trim(),
                  name: "新对象",
                  tags: [],
                  source_locator: { sheet: "人工编辑", field_locators: {} },
                };
                const asset = next.entities.assets[0]?.business_id ?? "";
                if (kind === "assets")
                  next.entities.assets.push({
                    ...common,
                    category: "Terminal",
                    criticality: "Medium",
                    lifecycle_status: "Active",
                  });
                else if (kind === "data_flows")
                  next.entities.data_flows.push({
                    ...common,
                    producer_asset_business_id: asset,
                    consumer_asset_business_id: asset,
                    supported_function_business_ids: [],
                  });
                else
                  next.entities.draft_threats.push({
                    ...common,
                    status: "Draft",
                    threat_type: "Tampering",
                    target_asset_business_id: asset,
                    standard_reference: "DO-356A",
                    rationale: "人工登记，待核对",
                  });
                updateDraft(next);
                setSelected(newId.trim());
                setNewId("");
              }}
            >
              加入草稿
            </button>
          </details>
          <h3>逐字段差异（相对当前服务端版本）</h3>
          <FieldComparison
            before={snapshot.model.entities}
            after={draft.entities}
          />
          {JSON.stringify(snapshot.configuration) !==
            JSON.stringify(draft.configuration) && (
            <div className="scroll-panel">
              <h4>分析配置变更</h4>
              <pre>
                修改前：{JSON.stringify(snapshot.configuration, null, 2)}
                {"\n"}修改后：{JSON.stringify(draft.configuration, null, 2)}
              </pre>
            </div>
          )}
          {state.conflict && (
            <div className="workbench-warning">
              <p>
                检测到版本冲突。请先检查上述相对当前版本的差异，决定保留哪些修改。
              </p>
              <button
                className="button"
                disabled={readonly || state.busy}
                onClick={() =>
                  updateDraft({
                    ...draft,
                    base_version: snapshot.model.revision_version,
                  })
                }
              >
                已检查差异，基于当前版本重新校验此草稿
              </button>
            </div>
          )}
          {state.editPreview && (
            <div>
              <p>
                {state.editPreview.ok
                  ? "服务端校验通过，可以保存。"
                  : "服务端校验未通过。"}
              </p>
              {state.editPreview.errors.map((e) => (
                <p role="alert" key={e}>
                  {e}
                </p>
              ))}
            </div>
          )}
          <div className="toolbar wrap">
            <button
              className="button"
              disabled={state.busy || readonly || state.conflict}
              onClick={() =>
                void perform(async () =>
                  patch({
                    editPreview: await workbenchApi.previewEdit(request()),
                  }),
                )
              }
            >
              服务端校验
            </button>
            <button
              className="button primary"
              disabled={
                state.busy ||
                readonly ||
                state.conflict ||
                !state.editPreview?.ok
              }
              onClick={() =>
                void perform(async () => {
                  await workbenchApi.commitEdit(request());
                  updateDraft(null);
                  await refresh();
                  patch({ message: "修改已保存；旧分析已过期，请重新分析。" });
                })
              }
            >
              保存到服务端
            </button>
            <button
              className="button"
              disabled={state.busy}
              onClick={() => {
                updateDraft(null);
                patch({ conflict: false });
              }}
            >
              放弃草稿
            </button>
            <button className="button" onClick={() => navigate("analysis")}>
              检查并重新分析
            </button>
          </div>
          <details>
            <summary>高级：JSON 编辑核心实体与分析配置</summary>
            <button
              className="button"
              onClick={() =>
                setJson(
                  JSON.stringify(
                    {
                      entities: draft.entities,
                      configuration: draft.configuration,
                    },
                    null,
                    2,
                  ),
                )
              }
            >
              载入当前草稿
            </button>
            <label className="field-stack">
              草稿 JSON
              <textarea
                className="input-field code-field"
                rows={12}
                value={json}
                onChange={(e) => setJson(e.target.value)}
              />
            </label>
            <button
              className="button"
              disabled={readonly || state.busy}
              onClick={() =>
                void perform(async () => {
                  const value = JSON.parse(json);
                  const { restoreDraft } = await import(
                    "../../shared/model/draftPersistence"
                  );
                  const parsed = restoreDraft(
                    {
                      ...draft,
                      entities: value.entities,
                      configuration: value.configuration,
                    },
                    draft.project_id,
                    draft.revision_id,
                  );
                  if (!parsed)
                    throw new Error(
                      "核心实体或分析配置格式无效；必须包含合法的 entities 和 configuration",
                    );
                  updateDraft(parsed);
                })
              }
            >
              更新草稿
            </button>
          </details>
        </>
      )}
    </section>
  );
}

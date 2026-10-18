import { inventoryFields, sheetNames } from "@attackgraph/contracts";
import { useWorkbench } from "../../app/WorkspaceProvider";
import { useWorkspaceContext } from "../../app/WorkspaceContext";
import { workbenchApi, downloadInventoryExample } from "../../api";
import { downloadInventoryTemplate } from "./workbookDownloads";
export default function InventoryWorkspace() {
  const { state, patch, perform, envelope, refresh, navigate } = useWorkbench();
  const scope = useWorkspaceContext();
  const preview = state.importPreview;
  const saved = !!state.snapshot?.model.entities.assets.length;
  return (
    <section className="panel">
      <span className="tag">01 / 数据导入</span>
      <h2>系统资产清单</h2>
      <p>
        {saved
          ? `已保存 ${state.snapshot!.model.entities.assets.length} 个资产 · 修订 v${state.snapshot!.model.revision_version}`
          : "下载模板或填写示例，导入到当前可编辑修订。"}
      </p>
      <label className="field-stack">转换适用范围<select aria-label="转换适用范围" className="input-field" disabled={state.busy} value={state.inventoryAircraftModel} onChange={e=>patch({inventoryAircraftModel:e.target.value,importPreview:null,importRequest:null})}><option value="">请选择已核对的资料范围</option><option value="DO356A-AMS">DO356A-AMS（已核对）</option><option value="UNCONFIRMED">其他机型 / 尚未确认</option></select></label>
      {state.inventoryAircraftModel==="UNCONFIRMED"&&<p className="workbench-warning">当前没有已验证的转换规则；可解析原始清单并查看诊断，但不会生成或保存 AMS 模型。</p>}
      {state.snapshot?.model.sources.map((s) => (
        <p key={s.id}>
          来源：{s.name} · {s.parser_name} {s.parser_version} · SHA256{" "}
          {s.content_hash}
        </p>
      ))}
      <div className="toolbar wrap">
        <button
          className="button"
          disabled={state.busy}
          onClick={() => void perform(() => downloadInventoryTemplate())}
        >
          下载空模板
        </button>
        <button
          className="button"
          disabled={state.busy}
          onClick={() =>
            void perform(async () =>
              downloadInventoryTemplate(await downloadInventoryExample()),
            )
          }
        >
          下载填写示例
        </button>
      </div>
      <p className="status workbench-warning">
        转换规则 do356a-ams/v1：仅适用于已核对的 DO356A-AMS
        清单；其他机型请先建立适用的转换规则。自动连接、威胁与目标均需核对。
      </p>
      <ol className="workbench-steps">
        <li>解析 Sheet 与表头</li>
        <li>校验字段与引用</li>
        <li>检查原始及推导预览</li>
        <li>提交保存</li>
      </ol>
      <label className="field-stack">
        上传 Excel（选择即解析，不会自动保存）
        <input
          className="input-field"
          type="file"
          accept=".xlsx"
          disabled={
            state.busy || !state.snapshot || state.snapshot.status !== "Draft" || !state.inventoryAircraftModel
          }
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (!file) return;
            patch({ importPreview: null, importRequest: null });
            void perform(async () => {
              const { parseCxfWorkbook } = await import("../../cxfWorkbook");
              const parsed = await parseCxfWorkbook(file, state.inventoryAircraftModel);
              const digest = await crypto.subtle.digest(
                "SHA-256",
                await file.arrayBuffer(),
              );
              const request = {
                contract_version: "inventory-import.v1" as const,
                conversion_profile: "do356a-ams/v1" as const,
                project_id: scope.projectId,
                revision_id: scope.revisionId,
                file_sha256: [...new Uint8Array(digest)]
                  .map((v) => v.toString(16).padStart(2, "0"))
                  .join(""),
                inventory: parsed.payload,
              };
              patch({
                importRequest: request,
                message: "解析完成，正在执行服务端校验。",
              });
              const result = await workbenchApi.previewInventory(request);
              patch({
                importPreview: result,
                message: result.ok
                  ? "预览已就绪；请核对后提交保存。"
                  : "校验未通过，请按诊断修改工作簿后重新上传。",
              });
            });
          }}
        />
      </label>
      {!state.snapshot && <p>请先选择或创建项目与修订。</p>}
      {state.importRequest && !preview && (
        <button
          className="button"
          disabled={state.busy}
          onClick={() =>
            void perform(async () =>
              patch({
                importPreview: await workbenchApi.previewInventory(
                  state.importRequest!,
                ),
              }),
            )
          }
        >
          重试服务端校验
        </button>
      )}
      {preview && (
        <div className="field-stack">
          <h3>模型预览：{state.importRequest?.inventory.source.file_name}</h3>
          <h4>原始清单记录</h4>
          <div className="workbench-counts">
            {Object.entries(preview.original_counts).map(([k, n]) => (
              <span className="pill" key={k}>
                {sheetNames[k as keyof typeof sheetNames]} {n}
              </span>
            ))}
          </div>
          <details>
            <summary>查看原始记录及 Excel 行号</summary>
            <pre className="scroll-panel">
              {JSON.stringify(state.importRequest?.inventory.workbook, null, 2)}
            </pre>
          </details>
          <h4>转换生成的资产</h4>
          <p>{preview.generated_counts.assets} 个</p>
          <h4>自动生成的连接</h4>
          <p>{preview.generated_counts.edges} 条（转换规则推导）</p>
          <h4>自动威胁候选</h4>
          <p>{preview.generated_counts.threats} 个，未经人工确认</p>
          <h4>推断目标</h4>
          <p>{preview.target_ids.join("、") || "无"}</p>
          <details>
            <summary>检查推导模型与来源</summary>
            <pre className="scroll-panel">
              {JSON.stringify(preview.model?.entities, null, 2)}
            </pre>
          </details>
          {preview.warnings.map((w, i) => (
            <p className="workbench-warning" key={i}>
              {w}
            </p>
          ))}
          {preview.error_details.map((d, i) => (
            <p role="alert" key={i}>
              {d.sheet} · Excel {d.row ?? "—"} 行 · {d.field} · {d.record_id}：
              {d.message}
            </p>
          ))}
          {preview.errors.map((d, i) => (
            <p role="alert" key={i}>
              {d}
            </p>
          ))}
          <p>
            已有编号采用 create-only
            校验，重复导入不会覆盖；更新请进入变更管理。
          </p>
          <div className="toolbar wrap">
            <button
              className="button primary"
              disabled={
                state.busy || !preview.ok || state.snapshot?.status !== "Draft"
              }
              onClick={() =>
                void perform(async () => {
                  await workbenchApi.commitInventory({
                    ...state.importRequest!,
                    ...envelope("inventory", state.importRequest),
                  });
                  await refresh();
                  patch({
                    importPreview: null,
                    importRequest: null,
                    message: "清单已保存到 Neo4j；可检查模型。",
                  });
                })
              }
            >
              提交保存
            </button>
            <button
              className="button"
              disabled={!saved || state.busy}
              onClick={() => navigate("analysis")}
            >
              检查模型
            </button>
          </div>
        </div>
      )}
      {saved && !preview && (
        <button className="button primary" onClick={() => navigate("analysis")}>
          检查模型 →
        </button>
      )}
      <details>
        <summary>模板字段帮助与引用关系</summary>
        {Object.entries(inventoryFields).map(([key, fields]) => (
          <div key={key}>
            <h3>{sheetNames[key as keyof typeof sheetNames]}</h3>
            <div className="scroll-panel">
              <table className="report-table">
                <thead>
                  <tr>
                    <th>字段</th>
                    <th>必填 / 类型</th>
                    <th>枚举 / 引用 / 示例</th>
                  </tr>
                </thead>
                <tbody>
                  {fields.map((f) => (
                    <tr key={f.key}>
                      <td>
                        {f.header}（{f.key}）
                      </td>
                      <td>
                        {f.required ? "必填" : "选填"} · {f.type}
                      </td>
                      <td>{f.enum.join(" / ") || f.reference || f.example}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </details>
    </section>
  );
}

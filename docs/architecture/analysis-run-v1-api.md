# Analysis Run v1 API 契约

状态：Implemented（Phase 4）  
契约版本：`analysis-run.v1`

## 作用域与对象

每次运行必须绑定 `project_id`、Draft `revision_id`、该 revision 的 `StandardProfileVersion`、同 revision 的 `SourceRecord`，以及不可变的 `AnalysisMethodDefinition(method_id, method_version)`。核心外壳为 `AnalysisRun` 和 `DerivedResult`；方法专用输入、配置与输出保存在版本化快照/payload 中，不替代通用核心实体。

已注册方法：

- `feature-rule-preview@0.1.0`（experimental）；
- `feature-topology-trace@0.1.0`（experimental）；
- `dfs-dps-attack-path@1.0.0`（qualified adapter）；
- `f3532-03-deterministic@2.0.0`（qualified adapter，受 ProfileConfiguration 开关约束；调用方只提供 options，事实由服务端按 project/revision 解析）。

## HTTP 接口

- `GET /api/v2/analysis/methods`：读取方法定义；
- `POST /api/v2/analysis/runs`：保存输入/配置/图/映射快照并执行方法；
- `GET /api/v2/analysis/runs?project_id=&revision_id=&run_id=`：读取历史运行、结果与 stale 状态；
- `POST /api/v2/analysis/derived-results/review-decisions`：对 DerivedResult 作出 ReviewDecision A；
- `POST /api/v2/analysis/promotions`：将 Reviewed 结果晋级为 Core Draft；
- `GET /api/v2/analysis/promotions?project_id=&revision_id=`：读取晋级来源和逐边验证。

所有写入要求 `command_id`、`expected_revision_version`、`actor`，经过 `RevisionUnitOfWork`，成功后产生 `AuditEvent`。同一命令和同一请求返回原结果；同一命令但 payload 不同返回 `COMMAND_PAYLOAD_MISMATCH`。

## 状态和责任边界

机器状态只能从 `Experimental`/`Candidate` 开始：

    Candidate → human ReviewDecision A → Reviewed / Rejected
    Reviewed → explicit Promotion → Core Draft
    Core Draft → independent Engineering ReviewDecision B → Reviewed / Approved / Rejected

方法 payload 中的 reviewer/review_status 仅表示输入数据状态，不能生成平台 `ReviewDecision`。晋级后的核心草稿必须保留 `origin=analysis_promotion`、来源 `AnalysisRun`/`DerivedResult`、`DERIVED_FROM` TraceLink，并在 API、报告和工作台中可见。

## 拓扑候选和完整性

`topology_only=true` 的 AttackPath 晋级必须提交攻击可行性说明，并为结果中的每条边提供语义说明和可解析到同 project/revision 的 `EvidenceRecord`。未截断且穷尽允许邻接关系时才允许 `completeness=complete`、`termination_reason=search_space_exhausted`；达到 hop/path/expansion 上限必须标记 partial 和对应终止原因。

有顺序语义的 `asset_ids`/`edge_ids` 不排序。结果摘要由方法版本对应的 canonicalizer 生成；输入、配置和实现指纹随运行归档。旧运行不可变，上游系统模型或工程案例写入会使其读取状态变为 stale，但不会覆盖历史结果。

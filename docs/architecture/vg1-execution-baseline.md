# VG-1 执行基线：首条可交付纵向链路

- 状态：Complete
- 完成日期：2026-10-11
- 分支：`Airworthiness-326A/356A`
- 前置：Phase 2 Complete
- 下一阶段：Phase 3 Ready

## 1. 已交付链路

```text
Project → Model → Revision → DO-326A/DO-356A StandardProfileVersion
        → SourceRecord → Asset/EvidenceRecord → DraftThreat → TraceLink
        → Frozen Baseline → UI 查看 / JSON 导出
```

本门槛只提前实现纵向切片所需的最小 `DraftThreat`、报告和冻结入口。它不包含 Phase 3 的完整 ThreatPoint/ThreatCondition/ThreatScenario、风险、目标、要求、控制和验证闭环，也不构成符合性声明或适航批准。

## 2. 实现边界

| 能力 | 实现 | 约束 |
| --- | --- | --- |
| 最小 Threat | 共享契约与 Neo4j `DraftThreat` | 固定为 Draft；关联目标 Asset；保存标准引用与来源定位 |
| 追踪 | `TraceLink` + `DERIVED_FROM_SOURCE` | 报告同时呈现 source/target，可由证据到威胁、由威胁到资产反查 |
| 报告 | `traceability-report.v1` | 稳定内容摘要不包含查看时间和查看者；导出记录本次 actor 与 generator version |
| 冻结 | `POST /api/v2/governance/revisions/freeze` | 使用 revision version 乐观并发，并绑定冻结前的报告内容 SHA-256 |
| 界面 | 报告中心 `VG-1 通用追踪链` | 支持 Revision/Baseline 二选一打开、冻结、查看和导出 |
| 演示 | `examples/vg1-controlled-source.json` + `npm run vg1:demo` | 仓库自有合成数据；幂等命令；无个人绝对路径和受限标准正文 |

## 3. API 与报告契约

- `POST /api/v2/governance/workspaces`：创建 Project、Model、Draft Revision 和 StandardProfileVersion。
- `POST /api/v2/system-model/import/commit`：导入 SourceRecord、最小系统对象、DraftThreat、EvidenceRecord 和 TraceLink。
- `GET /api/v2/traceability/report`：必须提供 `project_id`，并且 `revision_id`/`baseline_id` 恰好提供一个。
- `GET /api/v2/traceability/report/export`：以附件形式导出相同的 `traceability-report.v1` JSON。
- `POST /api/v2/governance/revisions/freeze`：用报告 `content_hash` 冻结 Revision。

报告包含 project、model、revision/baseline、StandardProfileVersion、SourceRecord、actor、Draft/Active/Frozen 状态、生成器版本、内容摘要、追踪链和审计事件。Baseline 报告会复算摘要，并给出 `matched`、`mismatch` 或 `not_frozen` 完整性状态。

## 4. Appendix D 来源确认

资料责任人于 2026-10-11 确认遗留数据来源为 **DO-356A Appendix D**。系统已执行受审且幂等的来源补录：

- SourceRecord：`DO356A-APPENDIX-D-SOURCE`；
- 来源标识：`DO-356A` / `Appendix D`；
- 关联实体：26；
- 已解决 `MISSING_SOURCE_LOCATOR`：3；
- 遗留挂接复核：27 个实体、0 条 Open issue、0 条诊断。

不在仓库或数据库中复制 Appendix D 正文。记录的 SHA-256 仅针对逻辑来源身份 `DO-356A|Appendix D`，并以 `content_hash_scope=logical-source-identity` 明示；将来若登记获授权文件，必须另存文件级摘要和受控位置。

## 5. 验收证据

| 检查 | 结果 |
| --- | --- |
| 迁移 | `0009_draft_threat_identity` 已应用并验证 |
| 后端单元测试 | 67/67 通过；边界测试覆盖 VG-1 核心文件无 F3532 import |
| Neo4j/HTTP 集成测试 | 12/12 通过；新增用例覆盖创建、导入、查看、冻结、导出 |
| 前端测试 | 5/5 通过 |
| 完整构建 | 后端、前端通过；仅保留既有 Vite chunk-size warning |
| 受控演示 | Baseline 内容摘要复算为 `matched`，2 条 TraceLink 可见 |
| 1440×900 | 报告入口、四列标识和追踪表格正常 |
| 1280×800 | 单列报告区正常，无页面横向溢出 |
| 390×844 | 文档 `scrollWidth` 等于可视内容宽度；表格横向滚动限制在 `.scroll-panel` |
| 工作区状态 | 离开并返回报告中心后，project/baseline 输入和已加载报告仍保留 |

浏览器控制台只观察到既有 ReactFlow 隐藏容器尺寸告警；VG-1 报告流程没有新增错误。现有 Vite 大 chunk 与 ReactFlow 隐藏状态告警继续作为前端技术债，不阻塞本门槛。

## 6. 出口判定

- 用户可在报告中心打开受控项目的 Revision 或 Baseline，并看到 DO-356A Draft 追踪链：通过。
- 导出含上下文、profile、来源、actor、状态、generator version 和审计：通过。
- 受控输入至报告可追踪且不依赖个人路径或隐式数据库状态：通过。
- 自动化覆盖创建、查看、冻结、导出：通过。
- VG-1 核心模块不依赖 F3532 adapter：通过。

VG-1 完成，Phase 3 进入 Ready。Phase 3 必须复用这里的 DraftThreat、TraceLink、SourceRecord、报告摘要和冻结语义，不得建立第二套临时实现。

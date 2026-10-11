# System Model v2 API 契约

- 状态：Accepted
- 契约版本：`system-model.v2`
- API 前缀：`/api/v2/system-model`
- 生效日期：2026-10-10

## 1. 责任边界

本 API 只承载标准无关的系统模型、来源记录、证据记录和类型化追踪。核心契约不包含 DO-326A、DO-356A、F3532 或具体工作簿字段。标准/模板差异留在 adapter；旧 API 继续通过 compatibility projection 提供只读兼容，不得反向成为 v2 核心模型。

共享运行时校验和 TypeScript 类型均由 `@attackgraph/contracts` 提供。后端路由、应用服务和前端 API 边界引用同一包，禁止复制第三份请求类型。

## 2. 端点

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| `POST` | `/api/v2/system-model/import/preview` | 在明确 project/revision 中解析并校验导入，不写数据库 |
| `POST` | `/api/v2/system-model/import/commit` | 以 command id、expected revision version 原子提交导入 |
| `GET` | `/api/v2/system-model?project_id=…&revision_id=…` | 读取 revision 内的通用模型和来源 |

完整示例见 [`examples/system-model-v2-import.json`](../../examples/system-model-v2-import.json)。

## 3. 核心语义

- `Asset`：通用资产，`category` 可扩展；不存在 F3532 必填字段。
- `Function`：支持父子分解。
- `Interface`：连接一到两个资产，可选择跨越 `SecurityBoundary` 或连接 `ExternalEntity`。
- `DataFlow`：显式 producer、consumer、可选 interface 和支持的 function；不再用一条含混的 `AssetEdge` 同时表示所有语义。
- `SecurityBoundary`：表达边界和成员资产。
- `ExternalEntity`：与威胁主体分离的系统外部实体。
- `SourceRecord`：记录内容哈希、解析器及其版本。
- `EvidenceRecord`：记录可引用证据，不等同于批准结论。
- `TraceLink`：有类型的实体间追踪；端点必须在同一 project/revision 中存在。

每个导入实体都通过 `DERIVED_FROM_SOURCE` 指向本次 `SourceRecord`。`source_locator` 可记录 sheet、row、column、JSON Pointer 和字段到源位置的映射；缺省时系统记录稳定的 JSON Pointer。

## 4. 写入规则

提交请求必须包含：

- `actor`、`command_id`；
- `project_id`、`revision_id`；
- `expected_revision_version`；
- `contract_version = system-model.v2`；
- 来源内容的 SHA-256 与解析器版本。

当前 v2 导入采用 create-only 语义：同类型、同 project/revision 的 `business_id` 已存在时返回冲突，不执行 upsert，也不做 last-write-wins。引用无法在当前导入或当前 revision 中解析时，整个事务回滚。

成功提交会使 revision version 增加一次并写入 `AuditEvent(SYSTEM_MODEL_IMPORTED)`。相同 `command_id` 和相同请求安全重放；同一 `command_id` 携带不同请求返回 `COMMAND_PAYLOAD_MISMATCH`。

## 5. 稳定错误码

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `INVALID_SYSTEM_MODEL_V2_REQUEST` | 请求不符合共享契约 |
| 404 | `SYSTEM_MODEL_SCOPE_NOT_FOUND` | project/revision 不存在或不匹配 |
| 409 | `SYSTEM_MODEL_IMPORT_CONFLICT` | 重复业务对象或未解析引用 |
| 409 | `REVISION_VERSION_CONFLICT` | expected version 已过期 |
| 409 | `REVISION_NOT_WRITABLE` | revision 不是 Draft |
| 409 | `COMMAND_PAYLOAD_MISMATCH` | command id 被不同请求复用 |

## 6. 非目标

- 不在本 API 内建立 Threat/Risk/Requirement 完整闭环；该工作属于 VG-1/Phase 3。
- 不自动把既有 F3532 节点改写为 v2 节点。
- 不解除旧全局写端点的隔离。
- 不把 preview 或导入结果声明为人工 Reviewed/Approved。

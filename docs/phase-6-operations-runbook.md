# Phase 6 评审与运维手册

## 1. 身份与角色

受控评审接口只接受 `Authorization: Bearer <API key>`。服务端从 `ASTRA_API_KEYS_JSON` 将密钥映射为固定的 actor、显示名称和角色，评审决定中的身份与角色不再来自请求正文。

支持的最小角色如下：

| 角色 | 能力 |
| --- | --- |
| `SecurityEngineer` | 建立 ReviewSession、评论、接受、拒绝或退回 |
| `AnalysisReviewer` | 建立 ReviewSession、评论、接受、拒绝或退回 |
| `EngineeringApprover` | 评论及正式批准/退回 |
| `ProjectAdmin` | 当前项目的全部评审动作 |
| `Auditor` | 只读评审内容并追加审计意见，不能作决定 |

同一 actor 不能既打开会话又关闭会话。API key 只配置在运行环境，不能写入仓库、日志或导出文件；轮换时先增加新 key、验证使用者，再移除旧 key并重启服务。

## 2. 受控评审流程

1. 在页面顶部设置 Project、Revision、Profile、Baseline 上下文和当前人的 API key。
2. 在“报告中心 → 受控评审”加载工程对象和评审队列。
3. 工程人员为一个带版本的对象打开 ReviewSession，可附两个候选业务编号。
4. 查看对象快照、候选 payload 和经 TraceLink 关联的 EvidenceRecord，追加署名意见。
5. 切换为独立批准人的 API key，由服务端校验角色并执行批准、接受、拒绝或退回。
6. 最终动作生成现有核心 `ReviewDecision`，包含 actor、role、timestamp 和 subject version，并通过 `AuditEvent` 保留命令哈希和幂等回执。

## 3. 可观测性

- `GET /health`：兼容存活检查，不访问数据库。
- `GET /api/v2/operations/health`：就绪检查，验证 Neo4j 连通性、迁移状态与迁移 checksum；异常返回 503。
- `GET /api/v2/operations/metrics`：返回进程启动时间、请求数、5xx 数、在途请求、p50/p95/max 延迟和状态码族计数。
- 每个 HTTP 请求完成后输出一行 JSON 日志，包含 request id、方法、路径、状态和耗时；不记录 Authorization、请求正文或 API key。

客户端可以传入合法 `X-Request-Id`，否则服务端生成 UUID；响应始终返回 `X-Request-Id`。

## 4. 备份恢复和迁移恢复

运行项目级恢复演练：

```bash
npm run phase6:recovery-drill
```

脚本只创建并操作一个新的临时项目，流程为：创建 → 捕获带类型属性、节点和关系的逻辑快照 → 写入临时文件 → 删除临时项目 → 恢复 → 重新捕获 → 比较语义 SHA-256 → 清理。恢复目标只要已经存在任何同项目数据就会拒绝覆盖。

迁移恢复检查：

```bash
npm run db:migrate -- plan
npm run db:migrate -- verify
```

发现 `failed`、`running` 或 checksum 不一致时停止启动受控写入，先查明原因；不得修改既有 migration 文件来“修正”账本。破坏性迁移仍需要显式 backup id。

## 5. 安全和剩余风险

- Excel 和 DOCX 只在浏览器本地解析；Excel 限 15 MB、DOCX 限 10 MB，并校验扩展名和空文件。
- Express 已升级到 5.3，消除旧版请求解析依赖的已知高/严重漏洞。
- `xlsx@0.18.5` 的上游 npm 包仍有无可用修复的高风险公告；受控试运行仅允许可信来源、受限大小的工作簿。正式发布前应评估受维护的替代解析器或隔离解析进程。
- `mammoth` 依赖链中的 `sprintf-js` 有中风险拒绝服务公告；文件大小限制降低暴露面，但 Phase 7 发布审计仍需跟踪替代或上游修复。
- 本阶段 API key 模型适合受控试运行，不替代企业身份提供方。OIDC/组织目录、密钥管理服务和细粒度项目成员关系属于后续部署增强。

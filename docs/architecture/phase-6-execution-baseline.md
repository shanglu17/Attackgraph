# Phase 6 执行基线：评审工作台、质量与运维

状态：Complete

完成日期：2026-10-15

前置：Phase 5 Complete

## 交付结果

Phase 6 将既有治理能力落实为一个可操作、可归责、可恢复的评审闭环：

    Project / Revision / Profile / Baseline context
      → versioned ReviewSession
      → candidate and EvidenceRecord inspection
      → attributed ReviewComment
      → independent authenticated actor
      → core ReviewDecision (approve / accept / reject / return)
      → AuditEvent + structured operations evidence

## 已实现能力

1. 四工作区共享项目、revision、profile、baseline 上下文；API key 只保留在当前页面内，不写 sessionStorage；
2. `review-workspace.v1` 契约定义 ReviewSession、ReviewComment、候选快照、证据摘要和受控决定；
3. 迁移 `0014_review_workspace` 建立 ReviewSession/ReviewComment 全局与作用域身份约束；
4. 受控评审接口通过 Bearer API key 将请求映射为服务端 actor、显示名称和角色，请求正文不能自报角色；
5. 打开会话和作出决定的 actor 必须不同，Approve 仅允许 EngineeringApprover 或 ProjectAdmin；
6. 最终动作复用核心 ReviewDecision，不建立第二套批准事实，并保留 actor、role、timestamp、subject version；
7. 评论、会话和决定均经过 RevisionUnitOfWork、乐观锁、command payload hash、AuditEvent 与幂等回执；
8. 评审工作台支持对象快照、最多两个候选 payload、TraceLink 关联证据、意见、批准、接受、拒绝和退回；
9. 增加 JSON 结构化请求日志、request id、运行指标和验证 Neo4j/迁移状态的 readiness 接口；
10. 项目级逻辑快照保留节点、关系、整数和时间属性，并拒绝覆盖已有项目；恢复演练对临时项目执行真实删除/恢复和语义哈希比对；
11. 前端依赖按 React、ReactFlow、XLSX、文档解析拆包，生产构建不再出现 500 kB chunk 告警；
12. Excel/DOCX 增加扩展名、空文件和大小防护；Express 升级至 5.3，修复旧传递依赖的高/严重漏洞。

## 出口门槛结论

| 门槛 | 结论 | 证据 |
| --- | --- | --- |
| 关键闭环具有 E2E 自动化证据 | 通过 | 真实 HTTP 创建会话、评论、同人拒绝、独立批准、读取和幂等重放 |
| 决定包含真实 actor/role/time/version | 通过 | 服务端 API key 身份映射；ReviewDecision 集成断言 |
| 备份恢复和迁移恢复通过 | 通过 | `phase6:recovery-drill` 语义哈希一致；迁移 0001–0014 verify 全通过 |
| 前端验证清单 | 通过 | 构建、前端测试、三档视口、选中态和页面级横向滚动检查 |
| 可观测性 | 通过 | readiness、metrics、结构化日志在 HTTP E2E 中验证 |
| 安全和性能检查 | 有条件通过 | Express 风险已修复、构建拆包完成；XLSX/Mammoth 剩余风险已限制并登记 |

## 验证记录

- `npm test -w @attackgraph/backend`：80 项通过；
- `npm test -w @attackgraph/frontend`：8 项通过；
- `npm run build -w @attackgraph/backend`、`npm run build -w @attackgraph/frontend`：通过；前端最大 chunk 低于 500 kB；
- `npm run test:integration -w @attackgraph/backend`：16 项通过；
- `npm run db:migrate -- verify`：`0001`–`0014` 全部通过；
- `npm run phase6:recovery-drill`：5 个节点、8 条关系恢复后语义 SHA-256 一致；
- 生产依赖审计：旧 Express 高/严重问题已消除；剩余 XLSX 高风险和 Mammoth 传递中风险按运行手册登记；
- `1440×900`、`1280×800`、`390×844`：页面级无横向滚动，四工作区和报告子页签选中态唯一，评审上下文及工作台在窄屏折行。

## 明确不属于 Phase 6

- 遗留数据正式 M0–M6 切换、双读退出、发布证据包和最终回退演练属于 Phase 7；
- 企业 OIDC、组织目录、外部密钥管理服务和更细项目成员矩阵属于部署增强；
- 平台的 ReviewDecision 和工作产品不能替代申请人、主管当局或授权标准的符合性与适航批准判断。

Phase 6 已通过出口门槛，Phase 7 转为 Ready。

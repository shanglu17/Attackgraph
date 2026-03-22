## Plan: Excel强校验导入、全路径展示与建模结果导出

在现有导入预览/分析/图谱接口基础上，新增“模板列头强校验（顺序可变）+整批强绑定拒绝”、移除前端路径展示上限、增加JSON导出最终建模结果（Graph+Analysis Paths+DO326A Links）。方案优先复用现有 Zod 校验、GraphRepository 数据聚合与前端 API 调用模式，避免引入新存储与复杂格式转换。

**Steps**
1. 需求冻结与边界确认（已完成）
   - 明确导入模板规则：仅要求模板列头存在，列顺序可变。
   - 明确强制绑定规则：AssetEdge 的 source/target 资产必须已存在，任一缺失则整批拒绝。
   - 明确导出目标：JSON，内容包含 Graph + Analysis Paths + DO326A Links。

2. 后端导入链路增强（Phase A，阻塞后续前端导入交互）
   - 在导入服务中增加模板列头白名单/必选列集合校验（顺序无关），输出明确缺失列/非法列错误。
   - 在导入 commit 实现中执行“整批原子校验”：先全量校验外键，再统一提交；任一 AssetEdge 引用不存在即拒绝整个批次。
   - 复用现有 graphChangeSet 校验与 GraphRepository 的外键校验逻辑，避免重复实现。
   - 统一导入错误模型（模板错误、字段错误、绑定错误）返回给前端。

3. 后端导出接口新增（Phase B，可与 Phase C 并行）
   - 新增导出路由（JSON），聚合：
     - Graph 快照（现有 getGraph）
     - DO326A Links（现有查询方法）
     - Analysis Paths（支持按 analysis_batch_id 过滤；无筛选则返回全部）
   - 设计导出响应结构（metadata + payload），包含导出时间、批次条件、数据条数统计。
   - 保持只读导出，不改变数据库状态。

4. 分析结果“全路径显示”改造（Phase C，可与 Phase B 并行）
   - 去除前端路径列表硬编码截断（当前 slice(0, 8)），改为完整列表渲染。
   - 保留现有单选高亮拓扑逻辑，仅扩展列表展示数量；必要时增加轻量性能保护（例如按分组折叠）但不改变交互语义。
   - 校验前端类型与后端返回一致，确保大结果集下排序与选择行为稳定。

5. 前端导出交互接入（Phase D，依赖 Phase B）
   - 在现有页面增加“导出建模结果(JSON)”操作入口。
   - 调用新导出 API，生成浏览器下载（文件名携带时间戳与可选批次号）。
   - 异常提示与成功反馈复用现有 toast/状态提示风格。

6. 联调与回归（Phase E，依赖 A/B/C/D）
   - 端到端验证：模板错误、绑定失败整批拒绝、分析全路径可见、导出文件结构正确。
   - 回归现有功能：分析运行、路径持久化、图谱加载、DO326A 链接展示。

**Relevant files**
- `apps/backend/src/services/importService.ts` — 增强模板列头校验与错误聚合；补齐 commit 行为入口。
- `apps/backend/src/routes/index.ts` — 导入 commit 落地路由与导出 JSON 路由注册。
- `apps/backend/src/repositories/graphRepository.ts` — 复用/扩展外键存在性校验与导出聚合查询。
- `apps/backend/src/types/api.ts` — 导入请求/导出查询参数与响应 schema（必要时）扩展。
- `apps/frontend/src/App.tsx` — 去除路径列表上限；新增导出按钮与下载流程。
- `apps/frontend/src/api.ts` — 新增导出 API 调用函数；必要的查询参数支持。
- `apps/frontend/src/types.ts` — 补充导出响应类型定义。
- `docs/requirements-spec.md` — 增补“导出能力”和“Excel导入commit已实现+模板校验规则”条目。

**Verification**
1. 导入模板校验
   - 用正确列头但乱序的文件导入：预览/提交通过。
   - 缺失必选列：返回模板错误并标明缺失列。
   - 包含非法列（若启用限制）：返回非法列列表。
2. 强制绑定（整批拒绝）
   - 构造一批数据中仅一条 AssetEdge 引用不存在 asset_id：commit 整批失败，数据库无部分写入。
   - 全部引用合法：commit 成功并可在图谱查询到变更。
3. 全路径展示
   - 运行 analysis 得到 >8 条路径：前端列表显示全部；可滚动浏览并逐条选中。
4. 导出
   - 触发导出后下载 JSON；检查包含 graph、analysisPaths、do326aLinks 三部分与 metadata。
   - 使用 analysis_batch_id 过滤时仅导出该批次路径。
5. 回归
   - 执行现有关键接口 smoke：`/graph`、`/analysis/attack-paths/run`、`/analysis/attack-paths/persist`、`/compliance/do326a-links`。

**Decisions**
- 已确认：模板校验采用“必需列存在即可，列顺序不敏感”。
- 已确认：强制绑定针对 AssetEdge→AssetNode，失败即整批拒绝（原子性）。
- 已确认：导出格式为 JSON，范围包含 Graph + Analysis Paths + DO326A Links。
- 包含范围：后端接口与前端入口闭环实现。
- 排除范围：Excel/CSV导出、权限系统、复杂分页/虚拟滚动优化。

**Further Considerations**
1. 导出路径范围策略
   - 推荐默认支持 `analysis_batch_id` 可选过滤，避免全量路径在大图场景下文件过大。
2. 模板版本演进
   - 推荐在模板中预留 `template_version` 列（当前可不强制），便于后续兼容变更。

# 正式工作台交付说明

基线：`43df6f8c28a8aef2798147736baf3a78422c21d4`。正式代码已迁回原工作目录 `E:/document/airness/project/Attackgraph`，继续使用原分支 `Airworthiness-326A/356A`，尚未提交。临时 worktree 注册和临时分支已移除；Demo 代码按用户要求丢弃，源文件及差异的仓库外备份保留。

## 启动

需要 Node.js 20、npm、Neo4j 5.26。首次安装使用 `npm ci`，然后 `npm run build`。

将根目录 `.env.example` 复制为 `.env`，填写本地 `NEO4J_URI`、`NEO4J_USERNAME`、`NEO4J_PASSWORD`。配置文件不进入 Git。真实环境先完成数据库备份，再检查迁移计划：

```powershell
npm run db:migrate -- plan
npm run db:migrate -- apply --actor local-engineer
npm run db:migrate -- verify
npm run dev
```

另开终端运行 `npm run dev:frontend`，打开 http://localhost:5173。Vite 默认将 `/api` 代理到本机 4000；可用 `ASTRA_BACKEND_URL` 调整开发/预览代理。部署时将 `/api` 反向代理至 Express，或构建时设置 `VITE_API_BASE_URL`。

本地也可用 `node scripts/serve-workbench-build.mjs` 提供已构建的前端并透明代理真实 `/api`，通过 `FRONTEND_PORT` 和 `ASTRA_BACKEND_URL` 设置端口及后端。该服务器发送真实 Gzip JS/CSS，验收用它核对压缩传输体积；不实现模型或数据库。

有破坏性迁移时，迁移器会停止。只有已经核对备份和目标库的维护者才可使用 `--allow-destructive --backup-id <实际备份编号>`。本轮没有修改迁移器或放宽旧写入隔离。

工程受控审查仍使用 `ASTRA_API_KEYS_JSON` 中配置的身份。在报告中心的高级工具中输入 API Key；认证信息只保留在内存，不写入草稿或浏览器持久化状态。

## 操作文档

* [导入、检查、修改、分析和导出演示](walkthrough.md)
* [项目归档、回收恢复和分析历史](project-management.md)
* [AMS 数据归属与攻击传播修正](propagation-policy.md)
* [23 条归属关系逐项核对与路径覆盖对照](ownership-review.md)
* [2026-10-20 增量验收与历史加载对比](improvements-2026-10-20.md)
* [九类 Sheet 填写指南](inventory-template.md)
* [新增接口及模型映射](../architecture/production-workbench.md)
* [验收及性能记录](acceptance.md)
* [构建与实际网络加载对比](performance.md)
* [阶段交付文件白名单及校验值（2026-10-18 历史快照）](delivery-files.tsv)
* [保留的后端项目专用逻辑](retained-backend-logic.md)

主流程只使用 v2 修订命令。下载填写示例不会写库；必须上传、预览，再明确提交。保存数据以 Neo4j 为准，浏览器中只持久化范围选择、界面选择及带基础版本的草稿。

## 独立验收数据库

`compose.acceptance.yml` 固定使用本机 17474 / 17687 端口及独立数据卷。先设置随机 `NEO4J_TEST_PASSWORD`，再运行：

```powershell
docker compose -f compose.acceptance.yml -p astra-production-acceptance up -d
$env:NEO4J_URI = 'bolt://127.0.0.1:17687'
$env:NEO4J_PASSWORD = $env:NEO4J_TEST_PASSWORD
$env:ASTRA_TEST_DATABASE = '1'
npm run db:migrate -- apply --actor acceptance-engineer
npm test -w @attackgraph/backend
npm test -w @attackgraph/frontend
npm run test:integration -w @attackgraph/backend
npm run test:workbench:integration -w @attackgraph/backend
```

首次空的可丢弃验收库仍须处理迁移器的破坏性确认；仅对这个已核对的独立空卷使用确认参数，不能照搬到已有业务库。`test:workbench:integration` 强制检查测试标记和端口。旧兼容集成测试在测试标记下创建并回收自己的读取夹具，不调用旧 seed 或全局提交接口。

浏览器验收：将后端指向该测试库，使用 `PORT=14000`；构建前端后用 `ASTRA_BACKEND_URL=http://127.0.0.1:14000` 启动 `npm run preview -w @attackgraph/frontend -- --host 127.0.0.1 --port 15173`，从根目录执行 `node apps/frontend/scripts/verify-workbench.mjs`。脚本使用本机 Chrome 与 Playwright，可通过 `CHROME_PATH`、`CODEX_BUNDLED_NODE_MODULES`、`WORKBENCH_URL`、`WORKBENCH_EVIDENCE` 配置。验收会在测试库创建独立项目，并输出截图、导出文件和模块加载清单到 `.tmp/workbench-ui`。

浏览器脚本要求 `ASTRA_TEST_DATABASE=1` 且只允许本机地址。全流程通过后可运行 `node apps/frontend/scripts/verify-workbench-context.mjs`，验证跨项目草稿、延迟响应、并发冲突和冻结只读。对比压缩传输时使用上述 Gzip 静态服务器代替 Vite preview。

## 边界

评分用于相对排序，不是实际成功概率。原 DFS 的跳数、目标筛选及边因子规则保持不变，完整性保守标注为 partial。超时与执行失败保存为 Failed 运行和诊断，不能解释成没有路径，也不能导出为当前成果。

AMS 转换仅支持明确选择的 `DO356A-AMS` / `do356a-ams/v1`。其他机型需要独立定义并验证转换。F3532 后端接口、兼容类型、脚本、历史迁移和资料保留；正式前端没有对应导入、生成或报表入口。

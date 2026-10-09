# 开发环境检查记录（2026-10-03）

## 2026-10-08 更新：Docker / Neo4j 已恢复运行

用户明确允许使用新数据库，不再恢复旧数据。已备份失效的 Docker WSL 目录链接与运行目录，重新初始化默认位置的 WSL 环境，拉取 `neo4j:5.26` 并创建 `attackgraph-neo4j` 容器及持久化数据卷。Docker 引擎 27.1.1、Neo4j 5.26.31 已运行。

- Docker 新系统目录：`C:\Users\HUAWEI\AppData\Local\Docker\wsl\main`，数据磁盘目录：同级 `disk`。
- 旧目录链接保留为 `C:\Users\HUAWEI\AppData\Local\Docker\wsl.before-rebuild-20261008`；旧临时目录保留为同级 `run.before-rebuild-20261008`。
- Compose 已移除过时的 version 字段，添加 `restart: unless-stopped`，Docker 引擎启动后数据库容器可自动恢复运行（手动停止的情况除外）。
- 使用后端 `.env` 中的凭据完成 Neo4j 认证、`RETURN 1` 查询及事务写入后回滚；未遗留检查节点。
- 后端开发服务已启动；`/health`、`/graph` 均返回 HTTP 200。
- 前端 `http://localhost:5173` 和 Neo4j 浏览器 `http://localhost:7474` 均返回 HTTP 200。
- 当前为新数据库，未导入历史图谱。数据库登录用户名为 `neo4j`，密码见 `apps/backend/.env` 中的 `NEO4J_PASSWORD`。

后续日常启动：先打开 Docker Desktop，再在项目目录分别运行 `npm run dev` 和 `npm run dev:frontend`。需要手动启动数据库时运行 `docker compose up -d`。

下方保留 10 月 3 日的检查和故障现场记录，其中数据库未恢复的状态已被本次验证结果取代。

## 结论

项目的 Node.js 依赖、前后端编译、后端自动化测试均通过。Python 辅助脚本环境已修复。10 月 8 日已完成 Docker、Neo4j 和前后端连通验证，可继续开发；旧数据未恢复，依赖安全审计技术债仍保留。

## 已完成检查

| 项目 | 实际结果 |
| --- | --- |
| Node.js / npm | E 盘安装，Node.js 20.15.1、npm 10.7.0 可执行 |
| npm 完整依赖树 | `npm ls --all` 成功，检查 624 个依赖树条目，无缺失或无效依赖报告 |
| 后端构建 | TypeScript 编译通过 |
| 前端构建 | TypeScript / Vite 构建通过，仅有规范中已知的包体积提示 |
| 后端测试 | 12 项全部通过 |
| 前端开发服务 | Vite 启动成功，localhost:5173 返回 HTTP 200，入口存在 |
| 核心模块 | xlsx 内存读写、mammoth 加载、Neo4j 驱动加载、esbuild 转换通过 |
| 新 Python | C:\Users\HUAWEI\AppData\Local\Python\pythoncore-3.14-64\python.exe，版本 3.14.7 |
| 项目 Python 环境 | `.venv-dev` 已创建，openpyxl 3.1.5 / et-xmlfile 2.0.0 已安装，pip check 通过 |
| Python 脚本 | 两个脚本语法通过，内存 Excel 中文读写通过，docs 中 8 个工作簿可读取 |
| 配置 | 后端 .env 存在；已补齐被 Git 忽略的根目录 .env，使 Compose 与后端数据库密码一致 |
| Git | 可运行；隔离环境内曾出现全局 ignore 文件权限提示，未阻碍项目检查 |

## 已修复事项

- 旧 `.venv/pyvenv.cfg` 指向已失效的 D 盘 MinGW，保留旧环境，另建 `.venv-dev`。
- 新增 `requirements.txt` 固定 Python 脚本依赖，README 添加 Windows 使用说明。
- 转换器取消 D 盘默认源文件，要求显式传入源文件；支持第二个输出路径参数。
- 两个 Python 脚本的默认输出改为相对脚本定位项目 docs，避免依赖固定盘符。
- Git 忽略 Python 虚拟环境和缓存。
- Docker 残留 socket 无法单独改名；已将临时 run 目录备份为 `C:\Users\HUAWEI\AppData\Local\Docker\run.backup-20261003`，重新创建运行目录。
- 检查发现 Docker WSL 注册 BasePath 指向不存在的 `D:\docker\docker_desktop`，系统盘实际在 `E:\Docker\docker-desktop\ext4.vhdx`。原注册已导出到 `.tmp/environment-check/docker-wsl-registration-before.reg`，曾将 BasePath 修正到 E 盘。

## 数据库恢复现场

检查开始时，E 盘存在约 41 GB 的 `E:\Docker\docker-desktop\disk\docker_data.vhdx`。随后 Docker 日志记录收到 UI 的 `Reset to factory defaults` 操作，WSL 注册被清除。再次检查时，该数据磁盘已不在原位置；约 710 MB 的 ext4.vhdx 系统盘仍在。

因此，先前的路径修复不能视为 Docker 恢复成功。当前仅含 BasePath 的残留注册字段也不构成完整 WSL 发行版。应先确定是否要恢复已删除数据，或允许重建数据库；恢复原数据时应避免继续向对应磁盘大量写入。未执行新数据库初始化、清空图谱或重新导入。

尚未完成后端启动、Neo4j 认证、原图谱完整性及数据库读写验证。截图中的报错属于 Docker 环境问题，独立于前后端编译和 Python 重装。

## 可用重建来源

- `docs/资产清单_v4_真实数据.xlsx` 等现有 Excel 清单。
- `docs/experiments/astra-aviation-threat-modeling-result-batch-1779257002655-2026-05-20T06-10-39-054Z.json`：导出元数据记载 132 个资产、199 条边、165 个威胁点、5 个合规链接、5332 条分析路径。
- `docs/experiments/attackgraph-modeling-result-batch-1774850525754-2026-03-30T06-02-21-587Z.json`：17 个资产、14 条边、4 个威胁点、5 个合规链接、45 条分析路径。

这些是历史导出，不能保证覆盖数据库删除前的最新状态。

## 依赖安全与其他限制

官方 npm 接口审计报告：18 个受影响包条目（12 高、3 中、3 低，无严重级），包含传递依赖。`xlsx` 当前审计无自动修复版本，部分修复涉及 Tailwind 主版本迁移；未执行可能影响兼容性的自动升级。这些是依赖技术债，不是分盘导致的缺包。完整报告在 `.tmp/environment-check/npm-audit.json`。当前 npm 镜像不支持审计，检查时临时使用官方接口，未修改全局镜像设置。

裸 `python` 仍解析到 `E:\minGw\ucrt64\bin\python.exe`（3.11.9）；旧 py 启动器未发现新安装的 Python。请使用下面的项目解释器，避免依赖全局 PATH。系统 PATH 还包含旧 D 盘 ARM 路径，但本项目未发现对它的依赖。

专用 `scripts/validate_f3532_03_generation.mjs` 需要 `CODEX_NODE_MODULES` 指向 Codex 的 artifact-tool 包目录。包目前存在，但默认读取桌面的 01/02/03 工作簿，桌面未发现这些输入，因此未执行真实工作簿集成验证。常规平台开发不依赖该辅助脚本。

## 后续开发命令

```powershell
# Python Excel 脚本（可直接使用，无需激活）
.\.venv-dev\Scripts\python.exe -m pip check
.\.venv-dev\Scripts\python.exe scripts/convert_source_to_v4.py "源工作簿路径"

# 前后端验证（已通过）
npm run build
npm test -w @attackgraph/backend

# 数据库恢复成功后，在两个终端分别运行
npm run dev
npm run dev:frontend
```

现有 Node 依赖无需因重装 Python 而全部重装。数据库恢复之前，前端可以启动，依赖数据库的功能会失败。

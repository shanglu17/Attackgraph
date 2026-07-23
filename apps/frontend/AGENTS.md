# Frontend Agent Rules

本文件作用于 `apps/frontend/**`。任何 Agent 修改前端前，必须先阅读
[`docs/frontend-development-standard.md`](../../docs/frontend-development-standard.md)。

## 强制规则

1. 保持四个顶层工作区：`analysis`、`imports`、`reports`、`changes`。新功能必须归入一个现有工作区；新增顶层工作区需要同步更新规范并说明信息架构理由。
2. 每个页面状态只显示一个主要工作区。不要把新面板直接追加到 `App.tsx` 页面底部，也不要让导入、分析、报告和编辑器同时展开。
3. `App.tsx` 是遗留编排文件，不得继续增长。新增非平凡 UI 必须放到 `src/features/<feature>/`；本次触及某个大型 JSX 区域时，优先把该区域提取为 feature component。
4. 业务组件不得直接请求后端；统一调用 `src/api.ts` 的类型化函数。跨组件共享的领域类型放在 `src/types.ts`。
5. 复用 `styles.css` 中已有的 `.panel`、`.button`、`.input-field`、`.toolbar`、`.status`、`.scroll-panel` 等基础类。禁止为了单个页面复制一套卡片、按钮或表单样式。
6. 布局必须支持三档检查：宽屏 `1440×900`、窄桌面 `1280×800`、移动端 `390×844`。不得依赖固定页面宽度，不得产生页面级横向滚动；大表格只能在自己的容器内滚动。
7. 交互控件必须有可见标签或 `aria-label`；选项卡使用 `role="tablist"` / `role="tab"` / `aria-selected`；加载中必须禁用会重复提交的按钮。
8. 中文文件统一保存为 UTF-8。不得提交乱码、仅靠颜色表达状态、无空状态的数据区或无错误反馈的异步操作。
9. 完成前至少运行 `npm run build -w @attackgraph/frontend`，并按规范完成视觉检查。构建的 chunk-size warning 是当前已知技术债，不得新增其他 warning 或 error。

## Agent 提交说明必须包含

- 修改归属的工作区与用户任务；
- 是否新增或复用了基础组件/样式；
- 构建结果与检查过的视口；
- 未解决的前端技术债。

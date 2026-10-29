# WebUI

通过 create-vue 创建的页面原型，尚未接入后端接口，用于验证统一打包的可行性。

## 本地开发与构建

- `npm ci`：按锁文件安装依赖。
- `npm run dev`：启动开发服务器。
- `npm run build`：检查应用类型并构建静态资源到 `dist/`。

统一打包脚本会将静态资源复制到 `apps/internal/web/webui/`，嵌入 Go 程序。
当前没有自动化测试，未保留模板附带的测试框架和示例状态管理代码。

## VSCode 开发配置

- 安装推荐插件 `Vue.volar` 和 `Vue.vscode-typescript-vue-plugin`
- [禁用 VSCode 内置 TypeScript 插件](https://vuejs.org/guide/typescript/overview.html#configuring-tsconfig-json)

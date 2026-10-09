# 资料保存的网页 CSRF 观察（2026-10-10）

这是一次 macOS Chrome 真账号的有限观察，不是更新后 SDK 的在线验收。
未使用 Windows；合成测试不代表平台接受。生产服务继续使用锁定构建，资料修改开关关闭。

## 操作与结果

- 操作员授权在自己的现有简介末尾添加一个空格，点击一次保存；不重试。
- `POST /aweme/v1/web/commit/user/` 返回 HTTP 200、业务代码 2166，平台明确拒绝，
  提示 2026-10-10 22:39 后再试。网页关闭编辑框，未修改简介。
- 随后网页请求 `GET /aweme/v1/web/user/profile/self/` 重新读取资料。
- 从打开编辑框前至保存后的网络观察中，没有发现独立的网页 CSRF 令牌获取请求。
  这不排除页面此前的初始化，也不能推广到所有抖音写接口。

## 请求结构

资料提交使用表单编码和 UTF-8 字符集。相关头名称是：

- `x-secsdk-csrf-token`
- `bd-ticket-guard-client-data`
- `bd-ticket-guard-ree-public-key`
- `bd-ticket-guard-version`
- `bd-ticket-guard-web-sign-type`
- `bd-ticket-guard-web-version`
- `x-tt-session-dtrait`
- `uifid`
- `Content-Type`、`Origin`、`Referer`、`Cookie`、`User-Agent`

此记录不保存 Cookie、签名、指纹、令牌或个人简介的值，也不保存完整请求、响应或 HAR。
采集时一次工具输出过滤漏掉了合并在单个文本节点里的部分头值；随后改成明确头名称白名单。
那些值没有写入本仓库或诊断文件，已进入的工具对话记录不能由本次代码修改撤回。

## 网页代码与 SDK 变更

在已加载的公开
[runtime_bundler_34_v2.js](https://lf-security.bytegoofy.com/obj/security-secsdk/runtime_bundler_34_v2.js)
中，`csrfWebToken` 的重写分支在头缺失时直接添加公共降级标记，覆盖 XHR 和 Fetch。
这不是从 Passport CSRF Cookie 获取的账号令牌，也不是一次先取令牌再 POST 的流程。
本次真实资料提交使用了这条头。SDK 的 `ProfileEditor.commit` 据此添加该头和表单字符集；
没有新增令牌请求、Cookie 导出、浏览器依赖或提交重试。

之前“缺少动态 CSRF 令牌最可能导致 403，网页一定先请求令牌”的说法只是猜测，
本次观察修正了其中的流程判断。新增头仍不证明 403 会消失：网页与桌面 SDK 的票据字段、
会话指纹、公共参数和签名环境仍有差异。不要伪造这些字段或复制操作员的凭证到专用账号。

## 验证与下一步边界

Node 24.16.0：`pnpm exec tsc --noEmit` 通过；聚焦 `profile-editor.test.ts` 和
`ticket-guard.test.ts` 的 128 项离线测试全部通过。覆盖资料头经真实请求组装路径保留、
绑定票据、限制请求目的地、业务限频、空正文 403 不重试且不回退到普通客户端。
头像上传凭证 GET 不附加该资料 POST 头。

没有在专用账号上再次提交，没有部署此分支，也没有开启 harness 的 `/简介`。
下一次专用账号提交必须经操作员单独同意；不将此前结果未知的请求自动重放。

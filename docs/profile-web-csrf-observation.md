# 资料保存的网页 CSRF 观察（2026-10-10）

这是一次 macOS Chrome 真账号的有限观察，不是更新后 SDK 的在线验收。
未使用 Windows；合成测试不代表平台接受。此节描述最初观察时的状态：当时生产服务继续使用原锁定构建，资料修改开关关闭。
后续部署、开启与只读排查见文末更新。

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


## 后续更新：部署后的 HTTP 200 空正文与只读排查

本轮不再提交简介，不更改限额、凭证或账本，也不重启服务。使用锁定 SDK 的当前保存
会话构造独立内存连接，无保存回调、无设备/证书生命周期，完成三次真实 GET；
响应正文只在内存解码，记录状态、长度、身份匹配和简介字数，未记录凭证或简介原文。

同一 `www.douyin.com/aweme/v1/web/user/profile/self/` 接口得到：

| 参数 | HTTP | 业务码 | 身份与简介 |
| --- | --- | --- | --- |
| SDK 桌面公共参数，`aid=339757` | 200 | 0 | UID 与已绑定专用账号一致，简介 0 字 |
| 官网网页基础参数，`aid=6383` | 200 | 8 | 无用户资料 |
| 保留所有桌面参数，仅把 `aid` 改为 `6383` | 200 | 8 | “未登录”提示，无用户资料 |

因此桌面登录恢复成功不能等同于网页应用会话可用；当前 SDK 请求环境中，改变应用
身份就不能获得已登录资料。不能简单把写入的 `aid` 改成 6383，或将再次扫码桌面登录
当成完整网页会话修复。GET 被接受也不能证明同一身份的 POST 写接口支持或已通过安全校验。

另以完整锁定实现和合成简介替换 `fetch` 做离线组装检查：仅一次 POST，表单只有
`signature`，中文、特殊字符、换行可无损还原；CSRF 公共标记、a_bogus 和 Session
REE 票据均在请求中，重定向为 manual。合成空正文 200 被原样归为 `empty`，不会
变成成功或触发重试。所有三次 GET 与离线组装后，持久化账号文件均与读取前一致。

官网当前公开脚本显示网页基础参数为 `aid=6383`、`device_platform=webapp`、
`channel=channel_pc_web`，公共请求拦截器使用默认版本 17.4.0、webid 和 uifid；
资料提交列在 `web_protect` 的票据消费路径和 Dtrait 消费路径中：
[公共参数与请求拦截器](https://lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/douyin_web/client-entry~c01d2505.57a98fe2.js)、
[网页安全初始化](https://lf-douyin-pc-web.douyinstatic.com/obj/douyin-pc-web/ies/douyin_web/client-entry~a8963009.f541c1c2.js)。
此前真实 Chrome 保存已观察到 `bd-ticket-guard-web-version`、
`bd-ticket-guard-web-sign-type`、`x-tt-session-dtrait`、uifid 和 Origin；
当前 SDK 的离线实际组装缺少这些头，并用桌面 `aid=339757`、darwin、channel=20002、
版本 1.2.1 和原生 Session 票据提交网页路径。这是已确认的实现错配，不能把不存在
守卫结果头当成认证通过。正式修复方向调整为：先建立同账号、可验证身份的网页应用
会话，再实现匹配的网页安全上下文，而非继续猜 CSRF 或调整本地次数。

边界：这三次 GET 能确认应用身份下的认证差异，离线检查能确认请求结构；它们不能
单独定位哪一条服务器校验制造了先前的空正文 200，也不能证明完整网页安全上下文
必然解决写入。HTTP 200 空正文仍无业务成功或回显证据，写入验收未通过。
北京时间 14:32 的 macOS 本地服务采样显示 QQ/独立 SDK 在线，收件、处理、监控
存活；功能开启及 24 小时 3 次上限保持原样，未知意图不重放。Windows 仍暂缓。


## 2026-10-10：按主人选择保持纯 Node，并验证同账号网页会话

主人要求离线测好后部署，由主人发起新的端到端测试，并明确拒绝新增浏览器运行时。
从该专用账号此前独立网页登录的私有保存状态恢复候选会话，只读 GET 先核对远端
UID 与当前绑定账号一致；恢复匹配的网页 P-256 密钥与 `web_protect` 票据，检查真实
密钥对和原网页缓存一致性摘要。没有借用操作员账号，没有启动浏览器或更改 IM 登录。
运行时仅显式读取该账号独立私有文件；一次性恢复工具与凭据均在 Git 外。

新增纯 Node 网页资料客户端及真实 Node 特征的 Dtrait，具体边界见 guide 的末节。
网页票据信封从桌面 `req_sign_ree/ts_sign_ree` 改为 `req_sign/ts_sign`，公钥使用
原始 EC 点；补齐 ECDH/HMAC（保留协议支持的 ECDSA 退路）、网页版本/签名模式头、
uifid、Origin、Dtrait 与已观察到的 CSRF 降级标记。每次业务写入前都只读核对身份
和会话，并持久化认证；失败时不发业务 POST，不退回桌面通路。

392 项聚焦测试通过，覆盖真实 ECDSA、ECDH/HKDF/HMAC、AES 包解码、中文表单、
身份/会话/显式守卫失败、持久化失败、取消、空正文与不重试。均为离线合成证据。
真实 macOS Node 只做一次服务器公钥证书请求及一次网页 self GET：HTTP 200、
业务码 0、UID 匹配、HMAC 模式 1；没有守卫结果/server-data 或 Dtrait token 头，
简介仍为 0 字，资料 POST 数为零。不能据此宣称写入修好或全部安全校验已通过。
Node 特征少于浏览器；是否接受资料写入仍由主人发起的新命令验证，Windows 暂缓。


## 后续主人命令：本地生命周期错误，未进入网页请求

15:31:22（北京时间）主人新 `/简介` 生成 36 字草稿，账本记录一次尝试、零核实、
`unknown/profile_unconfirmed`；有限诊断仅为 `sdk_error`，没有 HTTP 状态。
代码与新增完整 `Account.setSignature()` 离线测试确认上线后的资料回调误用了
仅允许登录中状态的检查，立即抛出“登录已取消”。此次不是新的空正文 200/403
平台结果，在线状态在 self GET/资料 POST 发出之前就被拦截。
修正仅变更该回调：保留在线/登录代次/原连接身份约束，登录阶段校验不放宽。
新增测试不再替换 ProfileEditor，覆盖完整上线→网页 GET→一次合成 POST，以及
GET 在途退出并重新登录后阻止旧客户端 POST。无真实资料重试或旧意图重放。


## 2026-10-10 15:52：主人新授权的单次直接 SDK 写入成功

按主人最新指令，使用上次 36 字简介原文作独立手动测试，不再发端到端命令。
私有新意图及可能发送标记持久化在唯一一次资料 fetch 之前；重跑保护拒绝重复
启动，不自动重试未知结果。独占同账号状态，并恢复真实受限 Account，原生与
网页预检均核对 UID；SDK 固定为 873fdc2，网页登录/票据字段及 Node Dtrait 不变。

唯一一次资料 POST：HTTP 200、正文 2321 字节、业务码 0、UID 匹配、36 字简介回显
与原文一致。独立网页 self GET 再次确认业务码 0、同一 UID、同一 36 字简介；
写前简介为 0 字。没有第二次资料提交或私信发送，旧应用意图及限额未更改。
响应仍没有守卫结果/server-data/Dtrait-token 头；写入确认来自业务回显和独立读取，
不来自头缺失。完整 Account→纯 Node 网页客户端路径的这一次 macOS 简介写入已通过。
新的自动命令端到端、长期认证续期、其他字段及 Windows 仍不能据此验收。

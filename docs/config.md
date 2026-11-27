# 配置

uta 有两份配置：`uta.toml` 决定怎么运行 sing-box，sing-box 配置决定流量怎么走。规则文件见[规则](rules.md)。

## uta.toml

```toml
[singbox]
binary = "sing-box"       # 可执行文件；只写名字时在 PATH 里找
config = ["sing-box"]     # 配置文件或目录，必填

[ports]
tproxy = 7893
dns = 7853

[kernel]
mark_mask = 0x3000
route_table = 7500
rule_priority = 5200
```

除了 `singbox.config`，都可以省略，上面写的就是默认值。

- `binary` 只写命令名时在 `PATH` 里找；带路径分隔符的相对路径和 `config` 里的相对路径都相对于 `uta.toml` 所在的目录。`config` 写目录时，读取其中所有 `.json` 文件，按文件名排序。
- `ports`：uta 给 sing-box 加的两个入站的端口，和本机其他服务冲突时再改。
- `kernel`：uta 用的包标记位（`mark_mask` 必须恰好包含两个 `1` 比特）、路由表号，以及从 `rule_priority` 开始连续 4 个 `ip rule` 优先级。只有和本机其他软件冲突时才需要改。

`uta.toml` 只在 uta 启动时读取，改完要重启 uta。

## sing-box 配置

### uta 加了什么

uta 在你的配置之前合并一段自己的配置：

| 内容 | 作用 |
|---|---|
| 入站 `uta-tproxy`（tproxy，端口 7893） | 被接管的连接从这里进入 sing-box |
| 入站 `uta-dns`（direct，端口 7853） | 被接管的流量发给本机解析器的 DNS 查询从这里进入，见 [DNS](dns.md) |
| `route.default_mark` | 给 sing-box 自己发出的连接打标记，uta 据此不再接管它们 |
| 一条路由规则 `{ "inbound": "uta-dns", "action": "hijack-dns" }`，排在你所有的路由规则之前 | 发到 `uta-dns` 的查询交给 sing-box 的 DNS 模块，由你的 `dns` 配置解析 |
| `log.disabled`、`log.output` | 日志输出到标准错误，uta 靠日志判断 sing-box 是否启动完成，再转发到 uta 自己的标准错误 |

除了这条路由规则，这几项以 uta 的为准，你的配置里写了也不生效。路由规则里可以用 `"inbound": "uta-tproxy"` 区分被接管的流量和你自己加的其他入站。

### DNS 劫持

被接管的程序如果直接查询外部 DNS 服务器（比如 `8.8.8.8`），这些查询和其他连接一样进入 sing-box。想让 sing-box 解析它们，在路由规则的最前面加上：

```json
{ "port": 53, "action": "hijack-dns" }
```

也可以先 `{ "action": "sniff" }`，再用 `{ "protocol": "dns", "action": "hijack-dns" }`，这样连非 53 端口的 DNS 也能接住。不加的话，这些查询按普通连接路由出去，不经过 sing-box 的 DNS。想让 DNS 完全不经过 sing-box，见 [DNS](dns.md#不经过-sing-box)。

### 日志级别

`log.level` 照常设置。设成 `warn` 或更高时，uta 让 sing-box 实际以 `info` 运行（它要看到 info 级别的启动日志），再把低于你设置的级别的日志过滤掉，uta 输出的日志和你设置的一样。不写 `log.level` 时 sing-box 会输出大量调试日志，建议写成 `info` 或 `warn`。

### FakeIP

配置了 `fakeip` 类型的 DNS 服务器时，uta 读取它的地址段：发往这些地址的连接只看普通规则，不受排除规则影响。见 [DNS](dns.md#fakeip)。

### 拆成多个文件

配置可以按部分拆成多个文件放在同一个目录里，比如：

```
sing-box/
  10-common.json        log、experimental
  20-dns.json           dns
  30-outbounds.json     出站
  50-route.json         route
  70-inbound-xxx.json   你自己加的入站，一个一个文件
```

sing-box 按文件名顺序合并：数组首尾相接，对象逐层合并，同一个值在多个文件里出现时以先出现的为准。所以 `route.rules`、`dns.rules` 这类有顺序的列表应当只写在一个文件里，否则规则的顺序就由文件名决定了。

### 路径和权限

- sing-box 的工作目录是 `uta.toml` 所在目录，配置里的相对路径相对于它。
- sing-box 以运行 uta 的用户身份运行。它要写的文件（`experimental.cache_file`、证书、下载的规则集）要放在这个用户能写的地方；配置所在的目录对它不可写时（比如按 README 部署的系统服务，`/etc/uta` 属于 root），写成可写目录下的绝对路径，那份部署里 `uta.service` 通过 `StateDirectory=uta` 自动创建了 `/var/lib/uta`。
- uta 把配置复制到运行目录后交给 sing-box，复制时保留原文件的权限。配置里有密码的话，按你的需要设置文件权限，只要运行 uta 的用户能读就行。

### 应用前的检查

`uta apply` 先用 `sing-box check` 检查合并后的配置，通不过就不应用。有些错误 `check` 查不出来，要到 sing-box 运行时才报，这时 sing-box 继续用原来的配置，uta 报错。sing-box 的日志和 uta 的输出在一起，以 systemd 服务运行时在 journal 里。

## 自己部署

仓库附带的 systemd 服务文件只是一种部署方式。以其他方式运行时，uta 需要的是：

- **启动**：`uta daemon --config <uta.toml> --rules <规则文件> --runtime-dir <目录>`（`--runtime-dir` 也可以通过 `RUNTIME_DIRECTORY` 环境变量传入）。运行目录放控制 socket 和 uta 组装好的 sing-box 配置，要可写。
- **权限**：`CAP_NET_ADMIN` 和 `CAP_NET_BIND_SERVICE`。可以由启动方以 ambient capabilities 授予（比如 systemd 的 `AmbientCapabilities`），也可以用 `setcap cap_net_admin,cap_net_bind_service=p` 设在 uta 程序文件上。uta 会把它们传给它启动的 sing-box。不需要 root。
- **网络**：在要接管的那个网络命名空间里运行，一个命名空间只能有一个 uta。
- **就绪通知**：设置了 `NOTIFY_SOCKET` 时，uta 在接管生效后发送 `READY=1`（systemd 的 sd_notify 协议）；没设置就不发。
- **停止**：收到 SIGTERM 或 SIGINT 时，uta 先撤掉内核规则再停止 sing-box。被强制杀掉后，下次启动会先清理残留，也可以执行 `uta cleanup`。
- **命令行**：`uta` 命令默认依次找 `$XDG_RUNTIME_DIR/uta/uta.sock` 和 `/run/uta/uta.sock`，在别处时用 `--socket` 或环境变量 `UTA_SOCKET` 指定。能连接这个 socket 的用户都能操作 uta，socket 的权限是 0660，谁能连由它所在的目录和属组决定。

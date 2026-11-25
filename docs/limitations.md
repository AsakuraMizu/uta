# 限制与排查

## 限制

**连接失败会被掩盖**

被接管的 TCP 连接，在 sing-box 连上目标之前，程序这一侧就已经连接成功了。sing-box 连不上目标时，程序看到的是连接建立后被断开，而不是连接失败。

最常见的后果是双栈的目标 IPv6 不通、IPv4 正常时，程序不会改用 IPv4（Happy Eyeballs 不起作用），要等 sing-box 超时后才出错。sing-box 里对 TCP 用 `reject` 也是同样的效果。

对策：直连的目标用 `!dst:` 在内核里放行（见[配方](recipes.md)），或者在 sing-box 里对这些域名只解析 IPv4。

**改规则只影响新连接**

已经建立的连接保持原来的走向，包括长期不断的 UDP 流，比如 Tailscale、游戏。要让它们按新规则走，重启对应的程序，或者用 `conntrack -D`删掉对应的连接跟踪记录（对进行中的 TCP 连接这样做会导致断连）。

**打洞**

P2P 程序的 UDP 经过 sing-box 后，对外的端口映射会变，打洞失败。需要直连的程序要排除，见[配方](recipes.md)。

**其他**

- 只接管 TCP 和 UDP。`ping` 之类的 ICMP 不经过 sing-box。
- 一台机器（准确地说是一个网络命名空间）只能运行一个 uta。多用户共用的服务器上，只有一个人能运行它。
- `uta run` 需要 systemd：普通用户要有 user manager，也就是正常登录的会话。
- `uta add` 或 `uta del` 恰好在回答 `y` 之后被强制杀掉时，规则文件可能已经改了但改动被回滚。`uta status` 会提示，执行 `uta apply` 即可。

## 排查

**先看状态**

```sh
uta status
```

显示 sing-box 是否在运行、当前生效的规则，以及规则文件或 sing-box 配置是否改过还没应用。

uta 加到内核里的东西被其他程序删掉时，`status` 会列出缺了什么，并以非零状态退出。路由规则被删（默认配置下 systemd-networkd 启动时会删掉不是它配置的规则）uta 会自己补回；nftables 表被删（比如重启 `nftables.service` 时执行了 `flush ruleset`）要重启 uta。

**看日志**

uta 把 sing-box 的日志和自己的输出一起写到标准错误。用仓库附带的 systemd 服务运行时：

```sh
journalctl -u uta           # 系统服务
journalctl --user -u uta    # 用户服务
```

`log.level` 为 `info` 或更低时，sing-box 的日志里有每个连接走了哪个出站。

**常见报错**

| 报错 | 原因 |
|---|---|
| `failed to connect to the daemon at ...: Permission denied` | 当前用户没有权限连接控制 socket。按 README 部署时，把自己加入 `uta` 组并重新登录，或用 `sudo` 运行 |
| `a uta daemon is running (pid ..., uid ...)` | 本机已经有一个 uta 在运行，可能是别的用户的 |
| `the daemon runs a different uta executable; restart the daemon` | 换了 uta 的程序文件但没重启 uta。重启即可 |
| `the daemon is busy: ...` | 另一个改动正在等待确认，用 `uta confirm` 或 `uta rollback` 处理它 |
| `confirming the change needs a terminal; ...` | 在脚本里运行时加 `--pending`（之后 `uta confirm`）或 `--yes` |
| `rolled back: failed to write ...` | 执行 `add`、`del`，或确认它们发起的改动时，当前用户对规则文件所在目录没有写权限。按 README 部署时要用 `sudo` |
| `nft` 报 `No such file or directory` | 缺少 nftables 需要的内核模块。常见于内核升级后没有重启，重启机器即可 |

**异常退出后有残留**

uta 被强制杀掉时，它加的 nftables 表和路由规则可能留在系统里。uta 下次启动时会先清掉它们；也可以执行一次 `uta cleanup`（需要 `CAP_NET_ADMIN`）。仓库附带的服务文件在服务停止后会自动执行 `uta cleanup`。

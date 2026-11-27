# AGENTS.md

uta 是 sing-box 的透明代理控制器：一个二进制，`uta daemon` 负责 sing-box 子进程和内核状态（nftables 表 `inet uta`、带专用 protocol 号的 ip rule 和路由），其余子命令都是经 unix socket 连接 daemon 的客户端。

## 机制与部署分开

只有任何主机上接管流量都离不开的（防回环、退出清理、确认窗口），或不了解 uta 内部就无法从外部实现的（nft 规则、sing-box 片段、cgroup 跟踪），才进 uta 本体。能用 systemd unit、命令行参数或 sing-box JSON 表达的留给部署方，示例放 `contrib/`，按部署机制命名。不为具体环境或共存软件写特判，先找能覆盖它的通用机制，例如 `!oif:` 选择器。

运行身份、目录和访问控制由部署方决定；源码里不写用户名、组名、路径，也不另做鉴权。控制 socket 固定为 0660，谁能连由所在目录和组决定；复制的配置保留源文件的权限。

## 与 sing-box 的边界

- uta 只生成一个路径排在最前的片段，里面是 uta 的入站和 `route.default_mark`。sing-box 合并多个配置文件时同一个标量以先出现的为准，所以片段里每个标量都会覆盖用户的同名设置；加字段前先确认这一点。
- 不改写用户的 sing-box 配置，不提供 DNS 或分流开关。只从 `sing-box merge` 的结果里读两类东西：uta 依赖的约定（入站标签不冲突，日志能输出就绪标记），和影响接管判定的 FakeIP 地址段。

## 不变量

- 已经带 fwmark 的包不接管；sing-box 自身流量、用户出站的 `routing_mark` 和其他打 mark 的软件都靠这一条避免回环。
- 排除规则对 FakeIP 地址段不生效：假地址只有 sing-box 能连，是否接管只看普通规则。
- TCP 连接和转发流量是否接管在连接建立时决定一次，之后靠 ct mark 延续；改规则只影响新连接。本机发出的 UDP 每个包都重新判定：别的 socket 可能沿用同一组地址和端口、加入旧的 conntrack 记录。被重定向到 `uta-dns` 的本机查询在 raw 里判定并放进单独的 conntrack zone，因为重定向绑在 conntrack 记录上。
- uta 退出时（包括因 sing-box 退出而 shutdown）清理自己的全部内核状态。sing-box 在运行而上游失败时，被接管的请求失败，uta 不把它改道直连。
- 磁盘上不记事务状态，内核状态随时能由配置重建；daemon 启动先 cleanup。cleanup 按 nft 表名和 protocol 号删除，不读配置。
- daemon 只依赖 `CAP_NET_ADMIN` 和 `CAP_NET_BIND_SERVICE`；后者不能省，透明 UDP 回包要绑定原目标的低端口（53、443）。

## 控制面

- 同一时间只有一个修改操作，冲突的请求立即返回 busy，不排队。
- 一个连接对应一个请求和一个事务，结果只发回这个连接。连接断开即取消（准备阶段）或回滚（提交后、确认窗口内）；提交阶段不在中途打断。
- 单线程 compio，`RefCell` 借用不跨 `.await`。子进程退出、信号、inotify 各由独立任务处理：sing-box 退出时直接撤掉接管，不等正在进行的修改操作。
- 出错路径都走同一条 shutdown。子进程 pid 单独保存，进程被回收后不再向它发信号。
- 控制协议只有一种格式，CLI 和 daemon 不是同一个可执行文件时直接报错。

## 工具链

`rust-toolchain.toml` 锁定 nightly（compio 的 `linux_pidfd` 需要），`rustfmt.toml` 也用了 nightly 才认的选项；升级时整体换日期，不混用 stable。

## 测试

- `cargo test` 只跑单元测试，覆盖配置和规则的解析与校验。
- 数据面、控制面和与 sing-box 的交互由 e2e 测试覆盖：`cargo test --test e2e`，不在默认测试集里。先 `cargo build`，再 `tests/e2e/lab.sh up` 构建镜像并部署拓扑，用完 `tests/e2e/lab.sh down`；只需要 Docker 权限。节点直接运行 `target/debug/uta`，挂载 `contrib/` 里的 unit 和配置，改了这些文件要重新 `up`。用例共用一套拓扑，靠文件锁逐个运行。
- 改了 nft、路由、DNS、进程监管或控制面的行为，跑覆盖它的 e2e 场景；只改解析或 CLI 文字时，单元测试就够。
- 拓扑节点不能叫 `host`：containerlab 会把端点 `host:<网卡>` 当成宿主机的网络命名空间，直接在宿主机上建网卡。

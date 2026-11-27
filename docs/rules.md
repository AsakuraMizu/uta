# 规则

规则决定哪些连接交给 sing-box。规则文件一行一条，`#` 之后是注释：

```
# alice 的所有连接
uid:alice
# docker 拉镜像
cgroup:/system.slice/docker.service
# 内网不走代理，但发往内网的 DNS 查询照样交给 sing-box
!dst:10.0.0.0/8,192.168.0.0/16 port:!53
```

一个连接被接管，当且仅当它命中至少一条普通规则，并且不命中任何一条 `!` 开头的排除规则。规则之间不分先后。例外是 sing-box 配置了 FakeIP 时，发往假地址的连接不看排除规则，见 [DNS](dns.md#fakeip)。

## 写法

一条规则由若干条件组成，用空格隔开，**全部满足**才算命中。在 shell 里写规则时记得加引号。

| 写法 | 含义 | 例子 |
|---|---|---|
| `kind:值` | 条件 | `port:443` |
| `kind:值1,值2` | 满足其中任意一个 | `port:80,443` |
| `kind:!值1,值2` | 不是其中任何一个 | `uid:!alice,bob` |
| `a-b` | 范围，用于端口、uid、gid | `port:8000-8999` |
| 行首 `!` | 整条规则是排除 | `!oif:wg0` |

普通规则至少要有一个未取反的来源条件，说明接管谁的流量；排除规则可以不写来源条件。同一条规则里同一种条件只能写一次，多个值用逗号隔开（如 `port:80,443`）。

## 条件

**来源：本机进程**

| 条件 | 匹配 |
|---|---|
| `local` | 本机所有进程 |
| `uid:用户` | 这些用户的进程。写用户名、uid 或 uid 范围 |
| `gid:组` | 以这些组为有效组的进程，比如用 `sg 组名 命令` 启动的 |
| `cgroup:/路径` | 这些 cgroup 及其下级里的进程。路径从 cgroup 根算起，`*` 匹配一段路径里的任意字符，比如 `cgroup:/user.slice/user-*.slice` |

**来源：经本机转发的流量**

| 条件 | 匹配 |
|---|---|
| `iif:网卡` | 从这些网卡进来的。末尾的 `*` 匹配前缀，比如 `iif:br-*` |
| `src:地址` | 来自这些地址或网段 |
| `mac:地址` | 来自这些 MAC 地址，只对直接相连的设备有效 |

本机来源和转发来源不能写在同一条规则里。

**其他条件**

| 条件 | 匹配 |
|---|---|
| `dst:地址` | 发往这些地址或网段 |
| `port:端口` | 发往这些端口 |
| `sport:端口` | 从这些端口发出 |
| `proto:tcp` 或 `proto:udp` | 协议 |
| `oif:网卡` | 正常路由时会从这些网卡出去的 |

`dst:!10.0.0.0/8` 这种只写了 IPv4 网段的取反条件，对 IPv6 连接总是成立，反过来也一样。

## 命令

```sh
uta add 'uid:alice port:443'      # 加规则并应用
uta del 'uid:alice port:443'      # 删规则并应用
uta apply                         # 手动改了规则文件或 sing-box 配置后，应用
uta status                        # 现在接管什么、sing-box 是否在运行
```

- `add` 和 `del` 支持一次传多条规则，按含义比较规则，和书写顺序无关：`port:443 uid:alice` 和上面那条是同一条。规则文件里注释和其他行保持原样。
- 用户名、组名在应用时解析成 ID，不存在会报错。用户或组删掉重建后 ID 变了，要再 `uta apply`。
- cgroup 会被持续跟踪，规则写好后新建的 cgroup 也会被接管。

### 确认

规则或 sing-box 配置有变化时，uta 先让它生效，然后问你要不要保留：

```
Keep this change? [y/N] (rolls back in 90s)
```

回答 `y` 就保留，规则文件也在这时写入。回答其他内容、90 秒内不回答，或者 uta 命令被中断（比如 SSH 断了），都会回滚到原来的状态。这样即使改动把你的 SSH 连接切断了，等一会儿也能自动恢复。

- `--timeout 秒数` 改等待时间。
- `--yes` 不询问直接保留。
- 新的 sing-box 配置启动失败时，sing-box 继续用原来的配置运行，uta 报错，不会进入确认。
- 有改动在等待确认时，其他改动一律被拒绝。

规则变化只影响新连接，已经建立的连接保持原来的走向。

### 稍后确认

不在终端里操作时（比如在脚本里），用 `--pending`：命令让改动生效后立即返回，改动等待确认，到时间没有确认就回滚。

```sh
uta add --pending '!dst:203.0.113.0/24'
# 检查网络、SSH 是否正常
uta confirm         # 保留
uta rollback        # 或者放弃
```

确认要从一个新的命令发出，所以只有改动之后还能操作这台机器，改动才会被保留：改动切断了你的 SSH 或网络，就发不出 `uta confirm`，改动到时间自动回滚。`--yes` 没有这层保护。

如果是 `uta add --pending` 或 `uta del --pending` 发起的改动，规则文件会在执行 `uta confirm` 时由当前客户端写入；因此 `uta confirm` 也需要规则文件所在目录的写权限（按 README 部署时即需要 `sudo`），否则写入失败并触发回滚。`uta rollback` 不写文件，不需要写权限。

交互式确认的过程中，也可以在另一个终端用 `uta confirm` 或 `uta rollback` 替它回答。

### 临时接管一条命令

```sh
uta run curl https://example.com
uta run                                        # 启动一个 shell，里面运行的东西都被接管
uta run --with cgroup:/system.slice/docker.service docker pull alpine
```

`uta run` 把命令放进一个单独的 systemd scope，命令运行期间接管这个 scope，命令结束就撤掉。

`--with 规则` 在命令运行期间再额外接管一条普通规则选中的流量（不能是 `!` 开头的排除规则）。上面的例子连带接管了 docker 服务（见[配方](recipes.md#本机进程)里的“拉 Docker 镜像”），`docker pull` 结束后就恢复原样。可以写多个 `--with`。

## 命令补全

把 `contrib/completions/` 里的文件复制到 shell 的补全目录（bash：`~/.local/share/bash-completion/completions/`；zsh：`fpath` 里的任一目录；fish：`~/.config/fish/completions/`），或者在 shell 的配置里加一行：

```sh
source <(COMPLETE=bash uta)       # bash：~/.bashrc
source <(COMPLETE=zsh uta)        # zsh：~/.zshrc
COMPLETE=fish uta | source        # fish：~/.config/fish/completions/uta.fish
```

除了子命令和参数，还能补全规则：`uta add` 和 `uta run --with` 补条件，以及用户名、网卡名、cgroup 路径、协议这些值；`uta del` 补规则文件里已有的规则。

- bash 默认把 `:` 当作分词的位置，规则要以引号开头才能补全，比如 `uta add 'uid:al`。也可以在 `~/.bashrc` 里加一行 `COMP_WORDBREAKS=${COMP_WORDBREAKS//:}`，之后不加引号也能补全。
- 多个条件的规则写在同一对引号里，引号内的每个条件都能补全，比如 `uta add 'uid:alice port:4`。补全出一个完整的值后，shell 会补上右引号和空格，要接着写下一个条件，先删掉这两个字符。

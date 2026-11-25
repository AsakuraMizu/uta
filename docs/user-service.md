# 以普通用户运行

uta 也可以作为 systemd 用户服务，以你自己的身份运行，只接管你选的流量，比如你的所有连接、某个服务，或者用 `uta run` 临时接管一条命令。改规则不需要 root，配置都在你的家目录里。

和系统服务相比：

- uta 需要的两项能力（`CAP_NET_ADMIN`、`CAP_NET_BIND_SERVICE`）设在程序文件上，安装时用一次 `sudo`，之后启动和改规则都不需要。
- 服务随你的登录会话启停。要开机就运行，执行 `loginctl enable-linger`。
- 一台机器只能运行一个 uta，共用的服务器上只有一个人能这样用。

## 安装

1. 安装 uta，给它两项能力，再装用户服务：

   ```sh
   install -Dm755 target/release/uta ~/.local/bin/uta
   sudo setcap cap_net_admin,cap_net_bind_service=p ~/.local/bin/uta
   install -Dm644 contrib/user/uta-setcap.service ~/.config/systemd/user/uta.service
   mkdir -p ~/.config/uta/sing-box
   ```

   能执行这个文件的用户都能用它拿到这两项能力，所以放在别人进不去的目录里，或者用文件权限限制谁能执行。

2. 写配置 `~/.config/uta/uta.toml`：

   ```toml
   [singbox]
   binary = "/home/alice/.local/bin/sing-box"    # sing-box 在 PATH 里的话可以省略这一行
   config = ["sing-box"]                         # 读取同目录下 sing-box/ 里的所有 .json
   ```

3. 写 sing-box 配置 `~/.config/uta/sing-box/config.json`，要求和系统服务一样，可以直接用 [README](../README.md#快速开始) 里的例子。

4. 建一个空的规则文件，启动：

   ```sh
   touch ~/.config/uta/rules
   systemctl --user daemon-reload
   systemctl --user enable --now uta
   ```

5. 试一下：

   ```sh
   uta status
   uta run curl https://example.com
   ```

## 接管什么

只想临时让某条命令走代理，规则文件留空，用 `uta run`（见[规则](rules.md#临时接管一条命令)）。

想让自己的所有连接都走代理：

```sh
uta add uid:alice
```

更多写法见[规则](rules.md)和[配方](recipes.md)。

## 升级

换了 `~/.local/bin/uta` 之后，新文件没有能力，要再执行一次 `sudo setcap`，然后重启服务：`systemctl --user restart uta`。仓库里的服务文件有变化时，同时更新 `~/.config/systemd/user/uta.service` 并执行 `systemctl --user daemon-reload`。

## 程序文件不能设能力时

能力存在文件的扩展属性里，NFS 等文件系统上设不了。这时可以改用 sudo 在启动时授予，前提是当前用户能免密码执行 `sudo setpriv`（服务里用 `sudo -n`，需要密码时会直接启动失败）。安装第 1 步时不执行 `setcap`，服务文件换成另一份：

```sh
install -Dm644 contrib/user/uta-setpriv.service ~/.config/systemd/user/uta.service
```

这样升级时不用再执行 `setcap`。

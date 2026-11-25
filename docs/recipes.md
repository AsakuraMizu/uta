# 配方

下面的规则都写在规则文件里，或者用 `uta add '规则'` 加。

## 网关

**接管整个局域网，个别设备除外**

```
iif:eth1
!src:192.168.1.50
!mac:02:00:5e:10:00:01
```

按 MAC 排除不受设备 IPv6 临时地址变化的影响。

**只接管某几台设备**

```
src:192.168.1.20,192.168.1.21
mac:02:00:5e:10:00:02
```

## 本机进程

**代理自己的所有连接，内网和本机的虚拟网卡除外**

```
uid:alice
!dst:10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7 port:!53
!oif:docker0,br-*,tailscale0
```

发往 Docker 容器、Tailscale 对端的连接走对应的虚拟网卡，用 `oif:` 排除比列网段省事。`port:!53` 让发往内网 DNS 服务器（比如局域网路由器）的查询仍然交给 sing-box。

**只代理某个服务**

```
cgroup:/system.slice/example.service
```

用户自己的服务在 `cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/example.service` 这样的路径下，可以用 `systemctl --user status example` 查看。

**按组代理：用 `sg` 启动的程序走代理**

```sh
sudo groupadd proxied
sudo usermod -aG proxied alice     # 重新登录后生效
uta add gid:proxied
sg proxied -c 'curl https://example.com'
```

**拉 Docker 镜像**

镜像是 dockerd 下载的，所以要临时接管 docker 服务：

```sh
uta run --with cgroup:/system.slice/docker.service docker pull alpine
```

可以写成 shell 函数，只让需要联网的子命令走 uta：

```sh
docker() {
  case "$1" in
    pull|push|login|build) uta run --with cgroup:/system.slice/docker.service /usr/bin/docker "$@" ;;
    *) command docker "$@" ;;
  esac
}
```

## 通用

**让某些网段完全不经过 sing-box**

本来就直连的网段，比如本地网络、本校或公司网络，可以在内核里直接放行：

```
!dst:198.51.100.0/24,2001:db8::/32 port:!53
```

- 连接失败会直接反馈给程序，不会像经过 sing-box 时那样先连上再断开，见[限制](limitations.md)。
- `port:!53` 让发往这些网段的 DNS 查询仍然交给 sing-box，否则这些网段里的 DNS 服务器会被直接访问，防污染失效。
- 这些连接不会出现在 sing-box 的日志和面板里。

**Tailscale 等需要打洞的程序**

uta 不接管已经带 fwmark 的数据包，本机的 tailscaled 会自己给连接打标记，因此 uta 不会接管它。局域网设备上的 Tailscale 经网关转发，它的 UDP 进入 sing-box 后端口映射会变，打洞失败，只能走中继。把它排除：

```
!iif:eth1 proto:udp sport:41641
```

41641 是 tailscaled 的默认端口，对端用 `tailscale status --json` 能看到每台设备实际用的端口。端口不固定的设备改用按设备排除：`!src:192.168.1.30 proto:udp`。游戏等其他 P2P 程序同理。

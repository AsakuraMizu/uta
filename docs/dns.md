# DNS

被接管的流量，它的 DNS 查询默认也交给 sing-box，由你的 sing-box 配置决定怎么解析。下面几种方式按需要选一种。

| 方式 | 适合 | 系统解析器的缓存和分域解析 | uta 停止后 |
|---|---|---|---|
| 默认 | 任何场景；只接管部分进程、又要它们的 DNS 经过 sing-box 时只能用它 | 被接管的流量用不到 | 照常用系统解析器 |
| 保留系统解析器 | 接管整机或网关 | 都保留 | 照常用系统解析器 |
| systemd-resolved 的上游指向 sing-box | 接管整机或网关，用 systemd-resolved | 都保留 | 恢复原来的上游 |
| sing-box 替代系统解析器 | 网关，不想再跑一个解析器 | 没有了 | DNS 不可用 |
| 不经过 sing-box | 只要代理流量，DNS 照旧 | 都保留 | 照常用系统解析器 |

## 默认

被接管的流量发出的 DNS 查询：

- 发给本机任意地址 53 端口的查询（比如 `127.0.0.53`，或者局域网设备发给网关 LAN 地址的），转到 `uta-dns` 入站；
- 直接发给外部服务器的，比如 `8.8.8.8`，和其他连接一样进入 sing-box。

前一种由 uta 自带的规则交给 sing-box 的 DNS 模块；后一种要在 sing-box 配置里加 `hijack-dns` 规则（见[配置](config.md#dns-劫持)）。没被接管的流量照常使用系统解析器。

被接管的程序因此完全绕过了系统解析器，系统里按网卡配置的分域解析也就对它们无效，比如 VPN 下发的内网域名、Tailscale 的 MagicDNS。需要的话在 sing-box 里把这些域名交回系统解析器：

```json
"dns": {
  "servers": [
    { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
    { "type": "local", "tag": "system" }
  ],
  "rules": [
    { "domain_suffix": ["ts.net", "corp.example"], "server": "system" }
  ],
  "final": "remote"
},
"route": {
  "default_domain_resolver": "system"
}
```

有多个 DNS 服务器时，sing-box 要求用 `route.default_domain_resolver` 指定出站服务器的域名用哪个解析。

注意：

- 如果 `/etc/nsswitch.conf` 的 `hosts` 行里有 `resolve`，glibc 程序直接通过 systemd-resolved 的接口解析，不发 DNS 包，uta 拦截不到。连接本身仍然会被接管，只是域名由系统解析器解析。想让这些查询也进 sing-box，就把 `resolve` 从 `hosts` 行去掉（保留 `dns`），让 glibc 改走 `/etc/resolv.conf` 发出真正的 DNS 请求。
- 浏览器自己的 DoH 和 DoT 是普通的加密连接，sing-box 看不到里面的查询。

## 保留系统解析器

接管整机（`local`）或网关时，可以让查询照常交给系统解析器，只接管解析器发往上游的查询：

```
local
iif:eth1
!dst:127.0.0.53,192.168.1.1
```

`127.0.0.53` 是 systemd-resolved 的地址，`192.168.1.1` 是网关的 LAN 地址，按实际情况改。这样解析器的缓存、分域解析都还在；解析器向上游查询时，这些查询被 `local` 接管，由 sing-box 解析。

注意：

- sing-box 里不能再用 `local` 类型的 DNS 服务器。它会把查询交回系统解析器，解析器再发往上游，又被接管回 sing-box，形成回环。
- 解析器发往其他链路的上游，比如 Tailscale 的 `100.100.100.100`，要用 `!oif:tailscale0` 这样的规则排除，否则这些查询也会被 sing-box 接手。
- 用 `!dst:` 排除某个网段时，如果解析器的上游 DNS 服务器也在里面，它的查询就不会再经过 sing-box。加上 `port:!53` 保留 DNS：`!dst:198.51.100.0/24 port:!53`。

## systemd-resolved 的上游指向 sing-box

uta 运行期间，让 systemd-resolved 把所有查询都交给 sing-box，uta 停止后恢复原样。查询照常经过 systemd-resolved，它的缓存和分域解析都还在，也不依赖解析器发往上游的查询被接管。

uta 以 systemd 系统服务运行时，给它的服务加一个 drop-in。按 README 部署的话，是 `/etc/systemd/system/uta.service.d/resolved.conf`：

```ini
[Service]
ExecStartPost=+sh -c 'mkdir -p /run/systemd/resolved.conf.d && printf "[Resolve]\nDNS=127.0.0.1:7853\nDomains=~.\n" > /run/systemd/resolved.conf.d/uta.conf && systemctl reload-or-restart systemd-resolved'
ExecStopPost=+sh -c 'rm -f /run/systemd/resolved.conf.d/uta.conf && systemctl reload-or-restart systemd-resolved'
```

然后执行 `systemctl daemon-reload`；uta 已经在运行的话，再 `systemctl restart uta`。

- systemd 256 起 systemd-resolved 支持 `reload`，不中断服务就能重新读配置；更早的版本不支持，`reload-or-restart` 会改成重启它，重启时有短暂的解析中断，缓存也会清空。systemd 255 的 systemd-resolved 收到 SIGHUP 也会重新读配置，可以把 `reload-or-restart` 换成 `kill -s HUP` 避免重启。
- uta 在接管生效后才通知 systemd 启动完成（服务要是 `Type=notify`，仓库附带的服务文件都是），`ExecStartPost` 在那之后才执行，不会把查询发给还没就绪的 sing-box。
- 改 systemd-resolved 的配置要 root，`+` 让这两条命令以 root 运行，所以这个做法只适用于系统服务。以其他方式运行 uta 时，做法相同：uta 就绪后写入这个配置并让 systemd-resolved 重新读取，uta 退出后删掉。
- `Domains=~.` 让所有查询都走这个上游，网卡上 DHCP 下发的 DNS 服务器不再被使用；systemd-networkd 重新配置网卡也不影响它。uta 停止或异常退出时，`ExecStopPost` 删掉这个配置，systemd-resolved 回到原来的上游。
- `7853` 是 `uta.toml` 里 `ports.dns` 的默认值，改过的话这里跟着改。
- sing-box 里不能用 `local` 类型的 DNS 服务器，原因和上一节一样。
- 被接管的程序发给 `127.0.0.53` 的查询默认仍然直接转给 sing-box，不经过 systemd-resolved。想让它们也经过 systemd-resolved，像上一节那样加 `!dst:127.0.0.53`（网关上再加 LAN 地址）。

## sing-box 替代系统解析器

在 sing-box 里加一个监听 53 端口的入站，并让它的查询都由 sing-box 解析：

```json
"inbounds": [
  { "type": "direct", "tag": "resolver", "listen": "::", "listen_port": 53, "reuse_addr": true }
],
"route": {
  "rules": [
    { "inbound": "resolver", "action": "hijack-dns" },
    { "port": 53, "action": "hijack-dns" }
  ]
}
```

然后关掉原来占用 53 端口的解析器，比如 systemd-resolved 的 `DNSStubListener=no`、停掉 dnsmasq，再把网关自己的 `/etc/resolv.conf` 指向 `127.0.0.1`，并让 DHCP 下发的 DNS 指向网关。

- `reuse_addr` 是必须的。被接管的设备发给外部 DNS 服务器的查询，sing-box 要以那个服务器的地址和 53 端口回复，监听在 `::` 的 53 端口会和这个回复冲突。只监听具体地址（比如 `192.168.1.1`）时可以不写。
- uta 或 sing-box 停止时，网关上没有 DNS 服务。

## 不经过 sing-box

只想代理流量、DNS 照旧时，加一条规则：

```
!port:53
```

发往 53 端口的查询都不再被接管，不管发给本机解析器还是外部服务器，都和没有 uta 时一样。按域名分流可以靠 sing-box 的 `sniff` 从连接里取得域名。DoT（853 端口）和 DoH（443 端口）是普通的加密连接，会和其他流量一样被接管；不想让它们进 sing-box，就另外排除。

## FakeIP

sing-box 的 FakeIP 对 A 和 AAAA 查询返回假地址段里的地址，程序连这个地址时，sing-box 换回域名再按域名拨号，包括直连的连接。

在已有的 `dns` 配置里加一个 FakeIP 服务器和一条规则，并让 sing-box 把假地址的对应关系存到磁盘：

```json
"dns": {
  "servers": [
    { "type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "2001:2::/48" }
  ],
  "rules": [
    { "query_type": ["A", "AAAA"], "server": "fakeip" }
  ]
},
"experimental": {
  "cache_file": { "enabled": true, "store_fakeip": true }
}
```

要拿到真实地址的域名（比如要用 `!dst:` 在内核里放行的直连目标），在这条规则之前加规则交给其他 DNS 服务器。

uta 从 sing-box 配置里读出 FakeIP 的地址段，`uta status` 会显示。发往这些地址的连接只要命中普通规则就会被接管，排除规则对它们不生效：假地址只有 sing-box 认得，不经过它就连不上。

注意：

- `store_fakeip` 要开。`uta apply` 改了 sing-box 配置时会重新加载 sing-box，不存到磁盘的话，之前发出去的假地址都会失效。
- 能拿到假地址的来源都要有普通规则选中。系统解析器的缓存是共用的（[保留系统解析器](#保留系统解析器)、[systemd-resolved 的上游指向 sing-box](#systemd-resolved-的上游指向-sing-box)），没被选中的程序也会拿到假地址；只接管部分进程时要补一条，比如 `local dst:198.18.0.0/15,2001:2::/48`。网关上没被选中的局域网设备同理。
- uta 停止后，程序和解析器缓存的假地址要等过期才会重新解析，这期间连不上。sing-box 回复假地址的 TTL 是 600 秒。
- 发往假地址的 `ping` 不通：uta 只接管 TCP 和 UDP。

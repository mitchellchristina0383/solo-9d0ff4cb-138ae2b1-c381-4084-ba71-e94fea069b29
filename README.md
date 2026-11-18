# 隔离测试网 DHCPv4 服务（FastAPI + SQLite）

为隔离测试网准备的 DHCPv4 服务：在容器内的**非特权 UDP 端口**（默认 `6767/udp`，
不是 67）服务**单个固定地址池**，处理 DISCOVER / REQUEST / RELEASE，返回
OFFER / ACK / NAK。自带网页控制台，可选择设备身份发送**真实 DHCP 报文**并查看
租约与事件。

所有示例地址都在文档保留网段 `192.0.2.0/24`，不会与外网冲突。

## 快速开始

```bash
docker compose up --build -d
# 打开 http://localhost:8080
```

Compose 除本服务外还会启动三个**陌生应答端点**（仅用于演练，不会确认任何租约）：

| 服务 | 宿主 UDP 端口 | 行为 |
| --- | --- | --- |
| `rogue-spoof` | `6768` | OFFER 携带**冒用的受信 Server Identifier** `192.0.2.2`，下发陌生网关 `198.51.100.1` |
| `rogue-late` | `6769` | 延迟 6 秒才应答，演示迟到报文不会混入下一轮 |
| `rogue-bad-xid` | `6770` | 用错误事务号应答，演示事务/身份核对 |

启动后网页的"定向探测"卡片会通过 `DHCP_PROBE_SEED_ENDPOINTS` 自动登记受信端点与三个
陌生端点，直接勾选发起即可。

```bash
# 查看状态
curl -s http://localhost:8080/api/health | python3 -m json.tool
curl -s http://localhost:8080/api/state  | python3 -m json.tool
```

Compose 会把 `6767/udp` 直接映射到宿主机（`0.0.0.0:6767`）。容器内同样是非特权端口，
不需要 `CAP_NET_RAW`、`NET_ADMIN` 或 `--privileged`，也不改写任何网卡地址。
如果宿主机上 6767 已被占用，改 `docker-compose.yml` 的 `ports` 左侧端口即可。

```bash
docker compose logs -f dhcp
docker compose down          # 保留数据卷
docker compose down -v       # 连租约数据一起清空
```

## 行为约定

- **单池单进程**：UDP 监听器与 Web API 运行在同一进程（`--workers 1`），共享同一份
  租约状态；SQLite 文件上还有进程级 `flock`，第二个实例会被拒绝启动。
- **OFFER 有有效期**（`DHCP_OFFER_TTL`，默认 60s）：有效期内该地址被预留，其他设备
  不会拿到，也不会重复分配；客户端重传 DISCOVER 时沿用同一预留（幂等）。
- **REQUEST 只能确认本设备仍有效的预留**：地址或归属不匹配返回 NAK；用 `ciaddr`
  续租同样核对归属；续租会刷新到期时间。选择其他服务器的 REQUEST 只撤回本方
  尚未确认的预留，绝不触碰已确认租约。
- **RELEASE 核对归属**：只有在 `ciaddr` 上是本设备、且来自本服务器的
  offered/bound 租约会被删除；否则静默忽略。
- **落库先于回复**：先做 `BEGIN IMMEDIATE` 事务（含清理过期行），`synchronous=FULL`
  提交成功后才构造 OFFER/ACK。提交失败则**不回复任何报文**（客户端超时重试），
  不会出现"已发 ACK 但库中无记录"。
- **重启不丢租约**：offered 与 bound 都落库。容器重启后已确认租约仍在，到期时间不变，
  其他客户端不能抢占，原客户端可继续续租；已过期的记录在下次事务中被回收。
- **并发**：所有分配/确认/释放都在同一把进程内锁 + SQLite 写事务中完成，
  状态表主键为地址，并有"每个客户端最多一条 active 租约"的部分唯一索引兜底。
- **地址池耗尽**时静默丢弃 DISCOVER（不伪造地址）。
- **定向探测只发 DISCOVER**：每轮生成独立事务号（XID）与探测设备身份（随机本地管理
  MAC + Client Identifier），只采信"本轮 XID + 本设备身份"且来源端点匹配的应答。
  可信度按**应答来源的 UDP 端点**判定：陌生端点即使冒用受信 Server Identifier，也判为
  `spoofed-identifier`，绝不算受信。轮次结束（完成/取消/超时）后只撤销本轮探测身份在
  本服务产生的 `offered` 预留；真实设备的 `bound` 租约不会被触碰，探测全程不发
  REQUEST、不确认租约。每轮使用独立的 UDP 套接字并按来源地址在用户态分发，旧轮套接字
  关闭后迟到报文无法进入新轮，证据按轮次持久化保留。

支持的消息类型：DISCOVER、REQUEST、RELEASE，另外对 DECLINE 做隔离、对 INFORM 返回
ACK。中继（giaddr 非零）请求会被忽略——本服务不监听 67/udp。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DHCP_POOL_START` / `DHCP_POOL_END` | `192.0.2.100` / `192.0.2.110` | 固定池的闭区间（最多 4096 个） |
| `DHCP_SUBNET_MASK` | `255.255.255.0` | 池必须落在该子网内 |
| `DHCP_ROUTER` / `DHCP_DNS` | `192.0.2.1` / `192.0.2.53` | 下发的路由与 DNS（DNS 可逗号分隔多个） |
| `DHCP_SERVER_ID` | `192.0.2.2` | Server Identifier，不能落在池内 |
| `DHCP_BROADCAST` | `192.0.2.255` | Option 28 |
| `DHCP_LEASE_TIME` | `120` | 确认租期（秒） |
| `DHCP_OFFER_TTL` | `60` | OFFER 预留有效期（秒） |
| `DHCP_DECLINE_QUARANTINE` | `300` | DECLINE 后隔离秒数 |
| `DHCP_UDP_PORT` / `DHCP_UDP_HOST` | `6767` / `0.0.0.0` | 监听地址（非特权端口） |
| `DHCP_DB_PATH` | `/data/dhcp.sqlite3` | 数据卷内路径 |
| `DHCP_SIM_TARGET_HOST` / `DHCP_SIM_TARGET_PORT` | `127.0.0.1` / 跟随实际监听端口 | 网页模拟器的发送目标 |
| `DHCP_SIM_TIMEOUT` | `1.5` | 网页等待响应的秒数 |
| `DHCP_PROBE_TIMEOUT` | `3.0` | 定向探测每轮等待窗口（秒） |
| `DHCP_PROBE_MAC_OUI` | `02:50:52` | 探测设备身份使用的本地管理 MAC 前三字节 |
| `DHCP_PROBE_SEED_ENDPOINTS` | 空 | 启动时自动登记的端点，格式 `名称\|主机\|端口\|受信(0/1)\|Server-ID;...` |
| `DHCP_ALLOW_FAILURE_INJECTION` | `0`（Compose 里设为 `1`） | 允许演练接口注入一次提交失败 |

### 陌生应答端点（rogue 服务）的环境变量

`app/rogue/server.py` 与主服务同一镜像、不同启动命令，仅应答 DISCOVER：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ROGUE_UDP_HOST` / `ROGUE_UDP_PORT` | `0.0.0.0` / `6768` | 监听地址 |
| `ROGUE_SERVER_ID` | `198.51.100.2` | Option 54；设成受信值即可模拟冒用 |
| `ROGUE_OFFER_IP` / `ROGUE_ROUTER` / `ROGUE_DNS` | `198.51.100.230` / `.1` / `.1` | 拟分配地址与陌生网关/DNS |
| `ROGUE_DELAY_SECONDS` | `0` | 延迟应答秒数，模拟迟到报文 |
| `ROGUE_REPLY_BAD_XID` | `0` | 置 `1` 时用错误 XID 应答 |

若用不同地址池启动却指向旧数据库，服务会拒绝启动并提示换 `DHCP_DB_PATH`，
避免把旧租约静默套用到新池。

## 网页控制台

`http://localhost:8080/`

- 地址池总览：每个地址的空闲 / 已预留 / 已确认 / 隔离状态与剩余时间。
- 发送 DHCP 报文：选择 DISCOVER / REQUEST / RELEASE、MAC（可加 Client Identifier）、
  Hostname、Requested IP、ciaddr、Server Identifier、XID；可发往本服务的 UDP
  监听端口，也可自定义主机与端口。发出的报文十六进制与解析后的响应会一并展示。
- 租约表与事件时间线（OFFER/ACK/NAK/RELEASE/过期/OFFER 过期/PROBE_WITHDRAW 等），
  每 10s 自动刷新，另有长轮询在状态变化时立即刷新。
- 定向探测：登记/删除受信与待核查 UDP 端点（名称、主机、端口、是否受信、登记
  Server Identifier），勾选端点发起真实 DISCOVER。结果按端点展示应答来源、报文类型、
  Server Identifier、拟分配地址、网关、判定（受信 / 非授权 / 冒用标识 / 身份不符 /
  未核实）与判定依据；进行中的轮次可取消，已收证据保留，未应答端点标记为未核实。

注意：网页发送的是**真实 DHCP 报文**，会占用/释放本服务的地址，但它不会修改运行
浏览器那台机器的网卡配置——这里演练的是服务端协议与租约逻辑。

## 演练脚本

`scripts/drill.py` 只依赖 Python 标准库，向运行中的 Compose 实例发真实报文：

```bash
python3 scripts/drill.py contend          # 归属、冒领 NAK、续租、释放
python3 scripts/drill.py race --clients 20  # 并发争抢（超出池容量也应静默且无重复）
python3 scripts/drill.py expire           # 等 OFFER 过期后回收、旧预留不能再确认
python3 scripts/drill.py simulate         # 通过网页 API 发真实报文
python3 scripts/drill.py probe            # 定向探测：冒用标识/迟到/错事务号/轮次隔离
python3 scripts/drill.py commit-failure   # 注入提交失败：必须不 ACK，重试后恢复

# 重启演练（两步之间执行 docker compose restart dhcp）
python3 scripts/drill.py restart-before
docker compose restart dhcp
python3 scripts/drill.py restart-after
```

配合 `docker compose logs` 可看到被拒绝/忽略的原因（NAK 原因、落库失败堆栈等）。

## 本地运行（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DHCP_DB_PATH=./data/dhcp.sqlite3 uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 1
```

务必保持单 worker（状态与 UDP 套接字都在进程内）。

## 测试

```bash
pip install -r requirements.txt httpx
python3 -m unittest discover -s tests -v
```

覆盖：报文编解码、OFFER 占用与过期、越权 REQUEST/续租/RELEASE、其他服务器选择、
重传幂等、并发争抢（线程屏障同时 DISCOVER / 同一客户端并发）、池耗尽、重启后租约
存活与不可抢占、第二实例锁、提交失败不发 ACK 且状态未污染、真实 UDP 往返、
网页 API 与过期回收、定向探测判定矩阵（受信/非授权/冒用标识/身份不符/非 OFFER）、
错事务号不计为应答、静默与超时端点标记未核实且证据保留、迟到应答不混入下一轮、
取消轮次保留证据、探测预留撤销且真实设备 bound 租约不受影响、端点登记 CRUD 与种子。

## 已知限制

- 只服务单个固定池；不支持中继、多子网、静态绑定、BOOTP、Option Overload。
- 服务本身不发起 ARP 探测/ICMP 冲突检测；DECLINE 由客户端上报后隔离地址。
- OFFER/ACK/NAK 一律单播回发到发来请求的 UDP 源地址；即使客户端设置广播标志，
  也不会发往 `255.255.255.255:68`（本服务只绑定非特权端口，无法占用 68/udp）。
  因此适用场景是隔离网内能直接与该端口通信的客户端/演练工具。
- 依赖客户端正确使用 Client Identifier / chaddr 标识自身；同一 MAC 伪造 Client ID
  视为不同设备（与 RFC 2132 的标识语义一致）。

# NetCheck

本机网络持续监测平台。定时检测到常用站点的访问延迟，逐跳定位链路慢点，展示节点归属地，并把每次结果落成时间序列画出走势曲线。

## 功能

- **一键检测**：并发测量本机到一组站点的 curl 分阶段耗时（DNS、TCP、TLS、首字节、下载），实时流式展示。
- **定时自动监测**：后台调度器默认**每 10 分钟**跑一次轻量检测（不含 traceroute / 在线归属地查询，保证低开销、不触发限流），间隔可在 5 分钟到 1 小时之间调整，也可随时暂停或立即执行一次。
- **趋势图**：纯 canvas 绘制（零前端依赖），按延迟中位数 / P95 / 下载速率 / 失败率查看，时间窗口支持 1 小时到 7 天。鼠标悬停查看某一时刻各站点数值。
- **逐跳链路分析**：对单个站点按需 traceroute，展示每一跳的延迟与 IP 归属地，定位链路上的慢点。
- **历史留存**：检测结果以紧凑 JSONL 记录持久化，保留 7 天，自动裁剪。

## 环境要求

- **Python 3.9+**，已安装 `fastapi` 和 `uvicorn`。其余全部是标准库。
- 系统命令 **`curl`** 和 **`traceroute`**（macOS / Linux 通常自带）。缺失时对应检测项会报错。

安装依赖：

```bash
python3 -m pip install fastapi uvicorn
```

## 启动

```bash
sh run_netcheck.sh
```

然后浏览器打开 <http://127.0.0.1:8777>。默认只监听本机，无需鉴权。

其它用法：

```bash
sh run_netcheck.sh --port 9000       # 自定义端口
sh run_netcheck.sh --host 0.0.0.0    # 暴露到局域网（无鉴权，谨慎使用）
```

启动脚本默认用系统解释器 `/usr/bin/python3`。如需指定其它已装好依赖的解释器，用环境变量覆盖：

```bash
NETCHECK_PYTHON=/path/to/python sh run_netcheck.sh
```

常驻后台运行：

```bash
nohup sh run_netcheck.sh > netcheck.log 2>&1 &
```

## 使用

1. 打开页面后勾选 **"定时自动检测"**（默认间隔已是每 10 分钟），或点 **"开始检测"** 手动跑一次。
2. 跑过一轮后，`data/netcheck_history.jsonl` 会生成，趋势图开始出现曲线。
3. 点某个站点卡片可展开，对它单独做 traceroute，查看逐跳延迟与归属地。

## API

服务默认绑定 `127.0.0.1:8777`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 前端页面 |
| GET | `/api/health` | 健康检查 |
| POST | `/api/check` | 运行一次完整检测，返回结构化结果 |
| POST | `/api/check/stream` | 流式（SSE）运行一次完整检测 |
| POST | `/api/trace/stream` | 对单个站点按需 traceroute，流式返回每一跳 |
| GET | `/api/history?since_seconds=N` | 取最近 N 秒内的历史记录用于画图（默认 6 小时，上限 7 天） |
| GET | `/api/scheduler` | 查询定时调度器状态 |
| POST | `/api/scheduler` | 开关调度器 / 修改间隔（`enabled`、`interval_seconds`） |
| POST | `/api/scheduler/run` | 立即执行一次定时检测，不等下个周期 |

批量检测（`/api/check`、`/api/check/stream`）同一时刻只允许一个运行，重复请求返回 429；按需 traceroute 最多同时 4 个。

## 项目结构

```
netcheck/
  server.py       FastAPI 应用：API 路由、调度器生命周期、SSE 桥接
  scheduler.py    后台定时调度器（守护线程，间隔可调）
  history.py      时间序列历史存储（JSONL，7 天保留）
  engine.py       检测引擎：curl 分阶段计时、traceroute、慢因诊断
  geoip.py        IP 归属地解析
  static/index.html  单页前端（零依赖）
network_monitor.py   底层纯函数库，被 engine 复用
run_netcheck.sh      启动脚本
test_network_monitor.py  网络监测函数的测试
```

## 安全说明

- 默认只监听 `127.0.0.1`，本机访问，无鉴权。
- 用 `--host 0.0.0.0` 暴露到网络时**没有任何鉴权**，仅在可信网络中使用。
- 客户端可指定检测目标，但所有 URL 都在服务端校验（仅允许 http/https、不含内嵌凭证），traceroute 只对引擎自己解析出的 IP 执行，客户端无法注入任意主机。
```

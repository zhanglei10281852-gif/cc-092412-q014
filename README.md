# 乡镇政务协同服务

这是一个面向乡镇综合服务中心的模块化后端，集中管理居民档案、政务事务、信访流转、公告、部门、用户、角色、权限、会话、审计和可恢复后台任务。项目使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存或消息队列。

## 主要模块

- 居民档案：登记、查询、更新和关联事务。
- 事务办理：受理、分派、退回、办结和部门责任查询。
- 信访流转：签收、分派、办理、审核、复查、催办和流转记录。
- 公告与部门：公告置顶、分类检索、部门信息及关联业务查看。
- 身份与权限：用户、角色、细粒度权限、会话令牌、账号停用和会话撤销。
- 紧急解锁：连续输错密码锁定后，可凭原因、有效期和目标会话范围发起解锁申请；由不同于申请人的安全管理员审批，高权限账号需第二人确认，批准仅清除本次锁定并使指定旧会话失效。
- 审计记录：关键身份操作留痕，并对口令和令牌等敏感字段做过滤。
- 后台任务：使用 SQLite 保存待执行任务，支持去重、租约、重试和完成回执。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

配置项均以 `TOWNSHIP_` 开头。可以复制 `.env.example` 后按需设置，默认数据库位于 `./data/township.db`。

## 初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动服务

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

首次部署可创建唯一的初始管理员：

```bash
curl -sS -X POST http://127.0.0.1:8432/api/auth/bootstrap   -H 'Content-Type: application/json'   -d '{"username":"admin","password":"Admin!23456","client_label":"initial-setup"}'
```

之后通过 `/api/auth/login` 获取会话令牌，并在管理接口请求头中使用 `Authorization: Bearer <token>`。

## 紧急解锁

节假日值班连续输错密码触发自动锁定后，不必等待自动解锁或由管理员直接改账号状态，可走带审批的紧急解锁流程：

- `POST /api/unlock-requests`：发起申请，必填 `reason`（原因）、`validity_minutes`（有效期，5–240 分钟）、`session_scope`（`all` 使目标全部旧会话失效，或 `current` 仅限申请人的当前会话，后者只能本人申请）。锁定账号仍可凭未过期的旧会话令牌为本人发起申请。
- 审批由不同于申请人、也不同于目标账号的安全管理员（持 `unlocks.approve` 权限，系统角色 `security_admin`）在 `POST /api/unlock-requests/{id}/decision` 完成；目标是高权限账号（administrator 角色或持有用户/角色/解锁等敏感权限）时必须由两名不同的安全管理员依次批准。
- 任一审批人在申请完成前权限失效（角色被收回或账号停用），申请立即终止；目标在审批期间被停用或锁定状态发生变化，同样终止。
- 批准只清除“本次”锁定（核对申请时的 `locked_until` 快照）并按范围撤销旧会话，不修改密码、不改变长期账号状态；拒绝、撤回、过期、终止均为唯一终态，重复或并发决定返回 409。
- `POST /api/unlock-requests/{id}/withdraw` 仅申请人可撤回；`GET /api/unlock-requests/mine` 查看本人申请，`GET /api/unlock-requests` 与 `/{id}` 供持 `unlocks.read` 的安全管理员/审计查看。
- 审计可串联对照：登录失败（含锁定标记）→ 解锁申请 → 批准 → 批准后的首次登录（登录事件回带 `unlock_request_id`，申请记录回写 `first_login_at`）。

## 测试

```bash
python -m pytest
```

测试覆盖身份初始化、登录、用户与角色维护、权限计算、账号停用后的会话撤销、审计脱敏、居民事务、信访状态流转、公告排序、后台任务去重与领取、数据库时间格式，以及紧急解锁的申请、单人/双人审批、拒绝撤回过期终止、旧会话失效、并发唯一终态和审计链。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
```

该命令在进程内启动应用并检查服务根路径与健康接口，适合部署前快速确认路由和数据库初始化是否正常。

## 目录结构

```text
app/
  api/             用户、角色、审计、认证和系统接口
  core/            时钟、安全、异常和分页能力
  repositories/    SQLite 查询与持久化读取
  routers/         居民、事务、公告、部门和信访业务接口
  schemas/         管理接口输入模型
  services/        身份、审计和后台任务领域服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、管理接口和原有业务回归测试
tools/             本地维护脚本
```

## 数据一致性

SQLite 连接默认启用外键、WAL、busy timeout 与同步写入策略。需要跨多张表更新的管理操作在即时事务中执行，失败会整体回滚。会话令牌只保存摘要；用户停用会撤销仍有效的会话。审计事件保存操作者、动作、资源、结果和前后状态，但不会保存明文密码或令牌。

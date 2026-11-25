后台点了强制下线，用户刷新一下页面又是登录状态，撤销像是没发生过：强制下线必须在下一个请求立即失效；撤销的粒度可以是单个会话，也可以是单台设备或整个账号；撤销一个会话时必须把它派生出来的刷新令牌一并作废，派生令牌不能再换取新的会话；已经撤销的会话不得再刷新，也不得再通过任何校验；每一次撤销都要留下可查询的审计记录，记录时间、原因与目标；批量撤销时每个目标各自独立处理，前一个目标的结果不得影响后一个目标。不变量有两条：会话被撤销之后，任何有效性校验都必须返回无效；对同一个会话重复执行撤销，结果必须完全一致。

## 数据模型

会话保存在 store 的 sessions 映射里，键是会话编号。每条会话包含 session_id、tenant_id、account_id、device_id、created_at、expires_at、revoked_at、revoke_reason 与 status。status 取 active 或 revoked。

派生令牌保存在 tokens 映射里，键是令牌编号。每条令牌包含 token_id、session_id、tenant_id、account_id、device_id、kind、issued_at、expires_at 与 revoked_at。kind 取 refresh 或 access。

审计记录保存在 audit 列表里，追加顺序就是发生顺序。每条记录包含 session_id、tenant_id、action、at 与 reason。

撤销结果保存在 revocations 映射里，键是会话编号。

## 接口

resolve_targets 接收 store、target 与 kind，返回这次目标覆盖的会话编号列表，结果按编号排序。kind 取 session、device 或 account。target 必须带有 tenant_id，并按 kind 带有 session_id、device_id 或 account_id。设备目标与账号目标只覆盖目标租户内的会话；单会话目标同样要求会话属于目标租户。目标不存在时返回空列表。

cascade 接收 store 与会话，返回该会话派生出来的全部令牌编号，包含刷新令牌与访问令牌。

revoke 接收 store、会话编号列表、当前时间与原因，逐个撤销会话并返回摘要。摘要包含 revoked、already_revoked、skipped 与 tokens 四个列表。撤销会话时要把会话状态置为 revoked，写入撤销时间与原因，级联作废该会话的全部派生令牌，写入一条审计记录，并让后续校验立即看到撤销结果。重复撤销同一个会话只计入 already_revoked，不重复写审计。

is_valid 接收 store、会话与当前时间，只有在会话存在、状态不是 revoked、没有撤销时间且尚未过期时返回 True，其余情况返回 False。

audit 接收 store 与会话编号，返回该会话的审计记录列表，按写入顺序排列。返回的记录是副本，调用方修改副本不会影响 store。

check_refresh 接收 store、会话与当前时间，只有在会话仍然有效且至少存在一个未撤销且未过期的刷新令牌时返回 True，其余情况返回 False。

validate_targets 接收目标列表，返回问题说明组成的列表，没有问题时返回空列表。检查范围包括目标列表为空、目标缺少租户、目标没有作用域编号、目标同时给出多个作用域编号、目标重复以及目标跨越多个租户。

revoke_batch 接收请求列表与当前时间，按顺序处理每个请求并返回摘要。每个请求包含 store、target、kind 与 reason，其中 kind 缺省为 session，reason 缺省为 batch。每个请求都要按自己的 target 重新解析会话，前一个请求的目标不得沿用到后一个请求。返回值是 results 映射，results 列表与请求一一对应，元素是 revoke 返回的摘要。

## 测试

在仓库根执行：

    python -m pytest tests -q

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 身份与会话 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |
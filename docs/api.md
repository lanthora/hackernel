# 接口文档

使用 SOCK_DGRAM 类型的 AF_UNIX Socket 通过 /tmp/hackernel.sock 对外提供服务,
请求数据包大小限制在1KB以内.对于超过大小限制的数据包和无效的请求不进行任何回应.
同时限制1024的并发(最大允许的未处理的请求个数),当超出并发限制后,将根据LRU策略丢弃连接.

## 测试

使用 openbsd-netcat 可以进行服务端接口验证.当得到预期输出可认为服务端运行正常.
此时可以Ctrl+C终止进程.各个语言也有对应的 Unix Domain Socket 库可以使用.

```bash
# 创建socket并写入 {"type":"user::test::echo"}
nc -uU /tmp/hackernel.sock <<< '{"type":"user::test::echo"}'
# 接收到响应 {"extra":null,"type":"user::test::echo"}
{"extra":null,"type":"user::test::echo"}
```

后续的接口仅描述请求与响应数据部分,不再展现 socket 连接部分

## 辅助字段

由于请求和响应是纯异步的,
请求增加了一个与业务无关(任何一个请求都可以携带这个字段)的 "extra" 字段.
这个字段中的值再响应时原样返回,方便进行异步的操作.
其中可以保存任何合法的Json数据结构.当不携带 "extra" 字段时,返回的值为 null.
确定响应所对应的请求的唯一方法就是使用 "extra" 字段添加标识, 服务不保证按序对请求进行响应.
响应中的 "code" 字段表示执行结果, 0 为正常.

不携带参数

```json
{
    "type": "user::test::echo"
}
```

携带基本数据类型

```json
{
    "type": "user::test::echo",
    "extra": 1
}
```

携带数组

```json
{
    "type": "user::test::echo",
    "extra": [
        "Alice",
        "Bob"
    ]
}
```

携带对象

```json
{
    "type": "user::test::echo",
    "extra": {
        "reply_to": "Alice"
    }
}
```

## 控制类

### 设置 token

设置 token 后的请求都需要携带 token 字段.
文档中的其他接口按照没有设置 token 的方式给出, 如果设置了token 需要自行添加.

```json
{
    "type": "user::ctrl::token",
    "new": "this is the token"
}
```

再次设置token,此时需要携带之前设置的token.
后台保持最近两个token有效,解决更换token时存在的多个进程间token不一致导致的问题.

```json
{
    "type": "user::ctrl::token",
    "token": "this is the token",
    "new": "this is another token"
}
```

### 退出服务进程

```json
{
    "type": "user::ctrl::exit"
}
```

## 进程类

### 开启进程防护功能

```json
{
    "type": "user::proc::enable"
}
```

### 订阅进程创建事件

订阅成功后执行任意命令可以收到事件.

```json
{
    "type": "user::msg::sub",
    "section": "kernel::proc::report"
}
```

订阅成功后会持续收到的进程创建事件.
"cmd" 字段通过 \u001f 分割,分别表示：
当前进程所在路径,可执行文件路径,进程启动的参数.示例中以 ls 命令为例.

```json
{
    "type": "kernel::proc::report",
    "cmd": "/root\u001f/usr/bin/ls\u001fls"
}
```

### 取消订阅进程创建事件

```json
{
    "type": "user::msg::unsub",
    "section": "kernel::proc::report"
}
```

### 订阅进程审计事件

进程审计事件订阅,退订流程与上述操作一致,不做赘述.
仅 section 字段不同,同属于订阅退订功能,与上述功能的差异在后面的接口描述中进行说明.
订阅后将根据事件持续推送,单个进程可多次订阅,
每个事件仅发送一次消息,退订次数与订阅次数一致时会停止推送.连接断开也会停止推送.

```json
{
    "type": "user::msg::sub",
    "section": "audit::proc::report"
}
```

### 调整进程防护策略

白名单外进程能否执行通过 judge 调整,白名单的概念在后续内容中说明.

|参数|含义|
|-|-|
|0|允许执行但不上报,即关闭该功能|
|1|允许执行并上报审计事件|
|2|禁止执行并上报防御事件|

这里的审计事件对应 `"section":"audit::proc::report"` 的订阅.
在没有白名单时,配置`"judge": 2` 将导致无法创建新进程.

```json
{
    "type": "user::proc::judge",
    "judge": 1
}
```

### 插入白名单

"cmd" 字段内容应该与进程审计事件中内容完全一致.

```json
{
    "type": "user::proc::trusted::insert",
    "cmd": "/root\u001f/usr/bin/ls\u001fls"
}
```

### 移出白名单

```json
{
    "type": "user::proc::trusted::delete",
    "cmd": "/root\u001f/usr/bin/ls\u001fls"
}
```

### 清空白名单

```json
{
    "type": "user::proc::trusted::clear"
}
```

### 关闭进程防护功能

```json
{
    "type": "user::proc::disable"
}
```

## 文件类

### 启用文件防护

```json
{
    "type": "user::file::enable"
}
```

### 设置防护文件

"perm" 用32位有符号数进行标记.目前仅使用了8位,从低到高分别表示.

|数位|含义|
|-|-|
|1|禁止读|
|2|禁止写|
|3|禁止删除|
|4|禁止重命名|
|5|审计读|
|6|审计写|
|7|审计删除|
|8|审计重命名|

示例中的14(DEC)为00001110(BIN),禁止写删除重命名,即为只读模式.
"perm" 字段为 0 即移除对该文件的防护设置.

"flag" 表示更新方式.

|值|含义|
|-|-|
|0|存在则更新,不存在则新增|
|1|新增,如果已经存在对路径的策略则更新失败|
|2|更新,如果不存在这条路径的策略则更新失败|


```json
{
    "type": "user::file::set",
    "path": "/etc/fstab",
    "perm": 14,
    "flag": 0,
}
```

### 订阅文件防护事件

```json
{
    "type": "user::msg::sub",
    "section": "kernel::file::report"
}
```

订阅后持续收到事件.表示某个文件操作触发了设置的文件防护策略.字段含义与设置中的一致.

```json
{
    "type": "kernel::file::report",
    "name": "/etc/fstab",
    "perm": 4
}
```

### 清空文件防护策略

```json
{
    "type": "user::file::clear"
}
```

### 关闭文件防护

关闭文件防护不清空文件防护策略,开启防护时保留的策略立刻生效.

```json
{
    "type": "user::file::disable"
}
```

## 网络类

### 启用网络防护

```json
{
    "type": "user::net::enable"
}
```

### 插入网络防护策略

|字段|范围|作用|
|:-|:-|:-|
|id|s32|删除时使用|
|priority|u8|根据优先级命中,值越小优先级越高|
|flags|s32|1:匹配入站, 2:匹配出站, 3:仅命中握手包, 4:仅命中不包含数据的TCP包|
|response|u32|0:丢弃, 1:放行|
|protocol|u8|IP层协议编号,如TCP为6|

通过"begin","end"标记的数值范围的均为闭区间.

```json
{
    "type": "user::net::insert",
    "id": 0,
    "priority": 0,
    "addr": {
        "src": {
            "begin": "0.0.0.0",
            "end": "255.255.255.255"
        },
        "dst": {
            "begin": "0.0.0.0",
            "end": "255.255.255.255"
        }
    },
    "protocol": {
        "begin": 6,
        "end": 6
    },
    "port": {
        "src": {
            "begin": 0,
            "end": 65535
        },
        "dst": {
            "begin": 22,
            "end": 22
        }
    },
    "flags": 1,
    "response": 1
}
```

### 移除网络防护策略

```json
{
    "type": "user::net::delete",
    "id": 0
}
```

### 清空网络防护策略

```json
{
    "type": "user::net::clear"
}
```

### 关闭网络防护

关闭网络防护不清空的所有网络防护策略,再次启动时保留的策略立刻生效.

```json
{
    "type": "user::net::disable"
}
```

# 接口文档

使用 SOCK_DGRAM 类型的 AF_UNIX Socket 通过 /tmp/hackernel.sock 对外提供服务,请求数据包大小限制在1KB以内.对于超过大小限制的数据包和无效的请求不进行任何回应.同时限制1024的并发(最大允许的未处理的请求个数),当超出并发限制后,将根据LRU策略丢弃连接.

## 测试

使用 openbsd-netcat 可以进行服务端接口验证.当得到预期输出可认为服务端运行正常.此时可以Ctrl+C终止进程.各个语言也有对应的 Unix Domain Socket 库可以使用.

```bash
# 创建socket并写入 {"type":"user::test::echo"}
nc -uU /tmp/hackernel.sock <<< '{"type":"user::test::echo"}'
# 接收到响应 {"extra":null,"type":"user::test::echo"}
{"extra":null,"type":"user::test::echo"}
```

后续的接口仅描述请求与响应数据部分,不再展现 socket 连接部分

## 辅助字段

由于请求和响应是纯异步的,请求增加了一个与业务无关(任何一个请求都可以携带这个字段)的 "extra" 字段,这个字段中的值再响应时原样返回,方便进行异步的操作,当不携带 "extra" 字段时,返回的值为 null.

不携带参数

```json
{"type":"user::test::echo"}
{"extra":null,"type":"user::test::echo"}
```

携带基本数据类型

```json
{"type":"user::test::echo","extra":true}
{"extra":true,"type":"user::test::echo"}
```

携带数组

```json
{"type":"user::test::echo","extra":[1,2,3]}
{"extra":[1,2,3],"type":"user::test::echo"}
```

携带对象

```json
{"type":"user::test::echo","extra":{"key":"value"}}
{"extra":{"key":"value"},"type":"user::test::echo"}
```

## 进程类

开启进程防护功能,返回 code 为 0 表示开启成功.

```json
{"type":"user::proc::enable"}
{"code":0,"extra":null,"type":"kernel::proc::enable"}
```

进程创建事件订阅.订阅成功后执行任意命令可以收到事件.
"cmd" 字段通过 \u001f 分割,分别表示：当前进程所在路径,可执行文件路径,进程启动的参数.示例中以 ls 命令为例.

```json
{"type":"user::msg::sub","section":"kernel::proc::report"}
{"code":0,"extra":null,"section":"kernel::proc::report","type":"user::msg::sub"}
{"cmd":"/root\u001f/usr/bin/ls\u001fls","type":"kernel::proc::report"}
```

取消进程创建事件订阅.

```json
{"type":"user::msg::unsub","section":"kernel::proc::report"}
{"code":0,"extra":null,"section":"kernel::proc::report","type":"user::msg::unsub"}
```

进程审计事件订阅,退订流程与上述操作一致,不做赘述.仅 section 字段不同,同属于订阅退订功能,与上述功能的差异在后面的接口描述中进行说明.
订阅后将根据事件持续推送,单个进程可多次订阅,但每个事件仅发送一次消息,退订次数与订阅次数一致时会停止推送.连接断开也会停止推送.

```json
{"type":"user::msg::sub","section":"audit::proc::report"}
{"code":0,"extra":null,"section":"audit::proc::report","type":"user::msg::sub"}
```

调整白名单外进程执行策略,白名单的概念在后续内容中说明在.
1.允许执行并上报审计事件; 2.禁止执行并审计事件; 其他值允许执行但不上报. 这里的审计事件对应 `"section":"audit::proc::report"` 的订阅.在没有白名单时,配置`"judge":2` 将导致无法创建新进程. __在确定能发送请求调整 judge 后,可以尝试设置为 2 观察系统变化__.

```json
{"type":"user::proc::judge","judge":1}
{"code":0,"extra":null,"judge":1,"type":"user::proc::judge"}
```

插入白名单, "cmd" 字段内容应该与进程审计事件中内容完全一致.

```json
{"type":"user::proc::trusted::insert","cmd":"/root\u001f/usr/bin/ls\u001fls"}
{"cmd":"/root\u001f/usr/bin/ls\u001fls","code":0,"extra":null,"type":"user::proc::trusted::insert"}
```

移出白名单.

```json
{"type":"user::proc::trusted::delete","cmd":"/root\u001f/usr/bin/ls\u001fls"}
{"cmd":"/root\u001f/usr/bin/ls\u001fls","code":0,"extra":null,"type":"user::proc::trusted::delete"}
```

清空白名单

```json
{"type":"user::proc::trusted::clear"}
{"code":0,"extra":null,"type":"user::proc::trusted::clear"}
```

关闭进程防护功能.

```json
{"type":"user::proc::disable"}
{"code":0,"extra":null,"type":"kernel::proc::disable"}
```

## 文件类

## 网络类

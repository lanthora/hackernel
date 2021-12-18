# Hack Kernel 

尝试在内核层面做些有趣的事情.

~~注意: 这是一个实验性的项目, 请自行评估风险.~~

## 构建项目

### 环境

* 架构: X86_64/ARM/ARM64
* 内核版本: Linux5.10及以上

### 依赖

* [nlohmann-json](https://github.com/nlohmann/json)
* [libnl](https://www.infradead.org/~tgr/libnl/doc/api/index.html#main_intro)

### 内核模块

在[内核模块代码目录](kernel-space/)执行命令安装.

```bash
make install
```

其他用法见[Makefile](kernel-space/Makefile).

### 服务程序

vscode打开[服务程序目录](user-space/)后,F5编译运行.

其他用法见[CMakeLists.txt](user-space/CMakeLists.txt).

### 客户端程序

还没有开始实现,并且近期也没有实现的计划.

服务端通过 Unix Domain Socket 对外提供服务. openbsd-netcat 可以发送出满足服务端要求的数据包.用简单的例子进行说明.

```bash
# 连接 AF_UNIX,SOCK_DGRAM 类型的服务端
nc -uU /tmp/hackernel.sock

# 发送json字符串
{"type":"user::proc::enable"}
```

## 计划

~~项目随缘,想到什么做什么,做到哪里算哪里.写上个计划假装很正式~~

把目前内核支持的功能都在服务端做出对应的接口,并形成接口文档供客户端调用.

## Licence

[GPL-2.0](https://spdx.org/licenses/GPL-2.0-or-later.html)


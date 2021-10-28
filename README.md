# Hack Kernel 

尝试在内核层面做些有趣的事情.注意这是一个实验性的项目,内核模块的高权限同样意味着高风险,文件系统出现错误可能导致不可逆的数据丢失与系统损坏.

## 特性

### 文件访问审计

处理文件相关的系统调用,审计文件操作行为

### 进程执行审计

处理进程启动相关的系统调用,审计系统进程启动

### 网络访问审计

通过netfilter实现简易防火墙,目前添加的一条有趣的规则是:根据TCP报文是否包含有效载荷进行过滤.

## 运行环境

* `X86_64/ARM/ARM64`架构
* Linux5.10及以上内核

## 计划

- [ ] 实与内核通信的守护进程


# Apps

## 构建

```bash
# 如果更新依赖时出现网络问题,可以设置使用国内镜像
export GOPROXY=https://goproxy.cn

# 构建
make
```

## 运行

编译后的二进制为 `/cmd/dirname/hackernel-dirname`, 其中 `dirname` 为 `cmd` 的子目录名.

```bash
# 运行示例程序,将显示进程审计事件
./cmd/sample/hackernel-sample
```

其他程序的运行可能需要配置文件,配置文件模板见 `configs` 目录.


## Web 管理控制台

请从仓库根目录运行 `make web`，确保前端资源先构建并嵌入 Go 二进制。运行时可通过 `hackernel-web -config /path/to/web.yaml` 指定配置；默认仍读取 `/etc/hackernel/web.yaml`。详情见 [WebUI 文档](../webui/README.md)。

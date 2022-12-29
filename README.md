# Hack Kernel

尝试在内核层面做些有趣的事情.

详细描述见[主页](https://hackernel.org/)

## 构建项目

### 环境

* 架构: AMD64/ARM/ARM64
* 内核: Linux 5.10 及以上,对应发行版版本可参考[维基百科](https://en.wikipedia.org/wiki/Linux_kernel_version_history)

### 依赖

* [nlohmann-json](https://github.com/nlohmann/json)
* [libnl](https://www.infradead.org/~tgr/libnl/doc/api/index.html#main_intro)

### 编译

* [内核模块](kernel-space/Makefile)
* [上层服务](user-space/CMakeLists.txt)

## 相关项目

* [uranus](https://github.com/lanthora/uranus)

## Licence

[GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html)

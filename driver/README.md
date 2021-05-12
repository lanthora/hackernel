
## 日志打印原则

不出现异常不打印日志

## 在虚拟机内可用，实体机内不可用的问题

在 include/uapi/asm-generic/unistd.h 中发现这样一句

```cpp
#define __NR_execve 221
__SC_COMP(__NR_execve, sys_execve, compat_sys_execve)
```

深入后发现，未开启__SYSCALL_COMPAT宏时，系统调用号_nr与原始的系统调用绑定_sys，否则与_comp绑定

```cpp
#ifdef __SYSCALL_COMPAT
#define __SC_COMP(_nr, _sys, _comp) __SYSCALL(_nr, _comp)
#define __SC_COMP_3264(_nr, _32, _64, _comp) __SYSCALL(_nr, _comp)
#else
#define __SC_COMP(_nr, _sys, _comp) __SYSCALL(_nr, _sys)
#define __SC_COMP_3264(_nr, _32, _64, _comp) __SC_3264(_nr, _32, _64)
#endif
```

对比sys_execve和compat_sys_execve的函数声明可见并不一致，对指针的错误操作会导致系统异常

```cpp
asmlinkage long sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

asmlinkage long compat_sys_execve(const char __user *filename, const compat_uptr_t __user *argv,
		     const compat_uptr_t __user *envp);
```

__SYSCALL_COMPAT 这个宏在哪里定义的呢。这个宏在tile体系结构中定义，现在这个体系结构已经被移除:https://lwn.net/Articles/749293/ 。现在版本的内核应该不会进入这个分支。

## 系统调用的参数

tools/include/nolibc/nolibc.h 中定义了各个参数对应的寄存器

rax: 系统调用号
rdi,rsi,rdx,r10,r8,r9: 分别对应前6个参数

目前还没有遇到需要7个参数的系统调用，等用到了再去查


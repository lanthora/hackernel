ifneq ($(KERNELRELEASE),)
obj-m :=hackernel.o
hackernel-objs :=core.o netlink.o syscall.o util.o sys_execve.o sys_open.o
else
KDIR :=/usr/src/linux

build:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod *.mod.o *.mod.c *.symvers *.order .*.cmd .*.d
endif 

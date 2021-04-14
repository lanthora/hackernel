ifneq ($(KERNELRELEASE),)
obj-m :=hackernel.o
hackernel-objs :=core.o netlink.o syscall.o sys_execve.o util.o
else
KDIR :=/usr/src/linux
default:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod *.mod.o *.mod.c *.symvers *.order .*.cmd .*.d
endif 

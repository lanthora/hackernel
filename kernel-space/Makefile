ifneq ($(KERNELRELEASE),)
obj-m :=hackernel.o
hackernel-objs :=core.o netlink.o syscall.o util.o process.o file.o
ccflags-y += $(HACKERNEL_MODULE_CFLAGS)
else
KDIR :=/lib/modules/$(shell uname -r)/build

release:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug:
	$(MAKE) -C $(KDIR) M=$(PWD) HACKERNEL_MODULE_CFLAGS="-DDEBUG" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif 

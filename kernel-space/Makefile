ifneq ($(KERNELRELEASE),)
obj-m :=hackernel.o
hackernel-objs :=core.o netlink.o syscall.o util.o comlayer.o process.o file.o net.o
ccflags-y += $(HACKERNEL_MODULE_CFLAGS)
ccflags-y += $(call cc-option,-fmacro-prefix-map=$(PWD)/=)
else
KDIR :=/lib/modules/$(shell uname -r)/build

release:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug:
	$(MAKE) -C $(KDIR) M=$(PWD) HACKERNEL_MODULE_CFLAGS="-DDEBUG" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif 

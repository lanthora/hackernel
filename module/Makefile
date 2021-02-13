ifneq ($(KERNELRELEASE),)
obj-m :=hackernel.o
else
KDIR :=/usr/src/linux
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -f *.ko *.o *.mod *.mod.o *.mod.c *.symvers *.order .*.cmd

endif 
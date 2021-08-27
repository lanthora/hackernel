ifneq ($(KERNELRELEASE),)

obj-m :=hackernel.o
hackernel-objs :=\
	base/main.o \
	base/netlink.o \
	base/util.o \
	handshake/core.o \
	handshake/netlink.o \
	process/core.o \
	process/netlink.o \
	file/core.o \
	file/netlink.o \
	net/core.o \
	net/netlink.o

ccflags-y += $(HACKERNEL_MODULE_CFLAGS)
ccflags-y += -I$(src)/include
ccflags-y += $(call cc-option,-fmacro-prefix-map=$(PWD)/=)

else

KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build
DRIVER_VERSION := 0.0.1

release:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	strip hackernel.ko --strip-unneeded

debug:
	$(MAKE) -C $(KDIR) M=$(PWD) HACKERNEL_MODULE_CFLAGS="-DDEBUG" modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: clean
	mkdir -p /usr/src/hackernel-$(DRIVER_VERSION)
	cp -r * /usr/src/hackernel-$(DRIVER_VERSION)
	dkms add -m hackernel -v $(DRIVER_VERSION)
	dkms build -m hackernel -v $(DRIVER_VERSION)
	dkms install -m hackernel -v $(DRIVER_VERSION)
	dkms status

remove:
	dkms remove hackernel/$(DRIVER_VERSION) --all
	rm -rf /usr/src/hackernel-$(DRIVER_VERSION)

endif 

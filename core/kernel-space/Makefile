ifneq ($(KERNELRELEASE),)

obj-m := hackernel.o
hackernel-objs += base/main.o base/netlink.o base/syscall.o base/ftrace.o base/watchdog.o
hackernel-objs += watchdog/watchdog.o
hackernel-objs += handshake/core.o handshake/netlink.o
hackernel-objs += process/core.o process/netlink.o process/utils.o
hackernel-objs += file/core.o file/netlink.o file/utils.o
hackernel-objs += net/core.o net/netlink.o

ccflags-y += $(HACKERNEL_MODULE_CFLAGS)
ccflags-y += -I$(src)
ccflags-y += $(call cc-option,-fmacro-prefix-map=$(PWD)/=)
# Original calls must keep a return address inside this module for the
# ftrace recursion check, including when building the legacy backend.
ccflags-y += -fno-optimize-sibling-calls

else

KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build
DRIVER_VERSION ?= $(shell grep -Po '(?<=^PACKAGE_VERSION=")(.*)(?="$$)' dkms.conf)

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
	dkms remove -m hackernel -v $(DRIVER_VERSION) --all
	rm -rf /usr/src/hackernel-$(DRIVER_VERSION)

endif 

# Makefile
KDIR := /lib/modules/`uname -r`/build
#KDIR ?= /opt/workspace/source_package/linux-5.15.0

modules:
	$(MAKE) -C $(KDIR) M=$$PWD V=1

clean:
	rm -f *.o *.ko

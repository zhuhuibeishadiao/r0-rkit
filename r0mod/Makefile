obj-m		:= r0mod.o
r0mod-objs	:= r0mod_utils.o r0mod_hooks.o

PWD			:= $(shell pwd)
KERNELDIR	:= /lib/modules/$(shell uname -r)/build

default: all

all:
	KCPPFLAGS="-I$(PWD)/../include/" \
	$(MAKE) modules \
		-C $(KERNELDIR) M=$(PWD)
	mkdir -p ../Release
	cp *.ko ../Release/

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)
	rm -f ../Release/*.ko

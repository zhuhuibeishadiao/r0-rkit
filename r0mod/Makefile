OLDPWD = $(PWD)

ifneq ($(KERNELRELEASE),)
	obj-m		:= r0mod.o
	r0mod-objs	:= r0mod_utils.o r0mod_hooks.o
else
	KERNELDIR	:= /lib/modules/$(shell uname -r)/build
	PWD			:= $(shell pwd)
default:
all:
	KCPPFLAGS="-I$(OLDPWD)/../include/" \
	$(MAKE) modules \
		-C $(KERNELDIR) M=$(PWD)
	mkdir -p ../Release
	cp *.ko ../Release/
endif

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)
	rm -f ../Release/*.ko

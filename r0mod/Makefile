obj-m += r0mod.o
r0mod-objs := r0mod.o r0mod_utils.o r0mod_module.o

OLDPWD = $(PWD)

all:
	KCPPFLAGS="-I$(OLDPWD)/../include/" \
	$(MAKE) modules \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

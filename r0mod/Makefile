OLDPWD = $(PWD)
TARGET = r0mod
obj-m += $(TARGET).o
$(TARGET)-objs :=	r0mod_hooks.o \
					r0mod_utils.o

all:
	KCPPFLAGS="-I$(OLDPWD)/../include/" \
	$(MAKE) modules \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

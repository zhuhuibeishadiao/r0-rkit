OLDPWD = $(PWD)
TARGET = r0mod
obj-m += $(TARGET).o

all:
	KCPPFLAGS="-I$(OLDPWD)/../include/" \
	$(MAKE) modules \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)

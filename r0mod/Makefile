OLDPWD = $(PWD)
obj-m := r0mod.o
r0mod-objs := r0mod.o r0mod_utils.o r0mod_hooks.o

default:
	@echo
	@echo "To start the build of r0mod:"
	@echo "	make all"
	@echo
	@echo "To clean the build of r0mod:"
	@echo "	make clean"
	@echo

all:
	KCPPFLAGS="-I$(OLDPWD)/../include/" \
	$(MAKE) modules \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)
	mkdir -p ../Release
	cp *.ko ../Release/

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)
	rm -f ../Release/*.ko

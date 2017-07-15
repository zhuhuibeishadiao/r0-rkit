OLDPWD = $(PWD)

default:
	@echo
	@echo "To start the build of r0mod:"
	@echo "	make (all OR TARGET)"
	@echo
	@echo "To clean the build of r0mod:"
	@echo "	make clean"
	@echo
	@echo "Supported targets:"
	@echo "	linux-x86	- Linux, x86"
	@echo "	linux-x86_64	- Linux, x86_64"
	@echo

obj-m += r0mod.x86.o
r0mod.x86-objs := r0mod.o r0mod_utils.o r0mod_module.o

all: linux-x86 linux-x86_64

linux-x86:
	KCPPFLAGS="-I$(OLDPWD)/../include/ -D_CONFIG_X86_" \
	$(MAKE) modules \
		ARCH=x86 -C /lib/modules/$(shell uname -r)/build M=$(PWD)
	mkdir -p ../Release
	cp r0mod.x86.ko ../Release

obj-m += r0mod.x86_64.o
r0mod.x86_64-objs := r0mod.o r0mod_utils.o r0mod_module.o

linux-x86_64:
	KCPPFLAGS="-I$(OLDPWD)/../include/ -D_CONFIG_X86_64_" \
	$(MAKE) modules \
		ARCH=x86_64 -C /lib/modules/$(shell uname -r)/build M=$(PWD)
	mkdir -p ../Release
	cp r0mod.x86_64.ko ../Release

clean:
	$(MAKE) clean \
		-C /lib/modules/$(shell uname -r)/build M=$(PWD)
	rm -f ../Release/*.ko

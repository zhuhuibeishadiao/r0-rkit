OLDPWD = $(PWD)

default:
	@echo
	@echo "To start the build of r0-rkit:"
	@echo "	make (all OR TARGET)"
	@echo
	@echo "To clean the build of r0-rkit:"
	@echo "	make clean"
	@echo
	@echo "Supported targets:"
	@echo "	x86	- Linux, x86"
	@echo "	x86_64	- Linux, x86_64"
	@echo

all: clean x86 x86_64

x86: clean-x86
	gcc -m32 -I$(OLDPWD)/../include/ main.c -o r0bin.x86
	cp *.x86 ../Release

x86_64: clean-x86_64
	gcc -m64 -I$(OLDPWD)/../include/ main.c -o r0bin.x86_64
	cp *.x86_64 ../Release

clean-x86:
	rm -f *.x86
	rm -f ../Release/*.x86

clean-x86_64:
	rm -f *.x86_64
	rm -f ../Release/*.x86_64

clean:
	rm -f *.x86*
	rm -f ../Release/*.x86*

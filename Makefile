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

all: x86 x86_64

x86:
	cd r0bin && make all
	cd r0mod && make linux-x86

x86_64:
	cd r0bin && make all
	cd r0mod && make linux-x86_64

clean:
	cd r0bin && make clean
	cd r0mod && make clean
	rm -rf Release/

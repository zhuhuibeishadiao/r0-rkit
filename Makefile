all:
	cd r0bin && make
	cd r0mod && make

clean:
	cd r0bin && make clean
	cd r0mod && make clean

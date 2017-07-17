OLDPWD = $(PWD)

all:
	gcc -I$(OLDPWD)/../include/ main.c -o r0bin
	cp r0bin ../Release

clean:
	rm -f r0bin
	rm -f ../Release/r0bin

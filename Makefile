all:
	gcc -Wall -g -o test test.c -lselinux

clean:
	rm test

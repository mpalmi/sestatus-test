all:
	gcc -Wall -g -o test test.c -lselinux -laudit

clean:
	rm test

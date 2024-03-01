CC := gcc
CFLAGS = -g -Wall -Werror

default:
	${CROSS_COMPILE}${CC} aesdsocket.c -o aesdsocket ${CFLAGS}
	
all:
	${CC} aesdsocket.c -o aesdsocket ${CFLAGS}

clean:
	rm -f aesdsocket *.o

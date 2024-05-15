CC := gcc
CFLAGS = -g -Wall -Werror
LDFLAGS := -pthread -lrt

default:
	${CROSS_COMPILE}${CC} aesdsocket.c -o aesdsocket ${CFLAGS} ${LDFLAGS}
	
all:
	${CC} aesdsocket.c -o aesdsocket ${CFLAGS} ${LDFLAGS}

clean:
	rm -f aesdsocket *.o

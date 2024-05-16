CC ?= ${CROSS_COMPILE}gcc
CFLAGS ?= -g -Wall -Werror
TARGET ?= aesdsocket
LDFLAGS ?= -lpthread -lrt

default:
	${CC} ${TARGET}.c -o ${TARGET} ${CFLAGS} ${LDFLAGS}
	
all:
	${CC} ${TARGET}.c -o ${TARGET} ${CFLAGS} ${LDFLAGS}

clean:
	rm -f ${TARGET} *.o

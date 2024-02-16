CC := gcc

default:
	${CROSS_COMPILE}${CC} -Wall writer.c -o writer
	
all:
    ${CC} -Wall writer.c -o writer

aarch64-none-linux-gnu-:
	aarch64-none-linux-gnu-${CC} -Wall writer.c -o writer

clean:
	rm -f writer *.o

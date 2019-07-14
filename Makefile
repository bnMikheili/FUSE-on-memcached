CC=gcc
FLAGS=`pkg-config fuse3 --cflags --libs`

all : Filesystem.o memcache.o
	$(CC) Filesystem.o memcache.o -o cachefs  $(FLAGS)

memcache.o : memcache.c memcache.h 
	$(CC) -c memcache.c $(FLAGS)

Filesystem.o : Filesystem.c 
	$(CC) -c Filesystem.c $(FLAGS)

clean :
	rm *.o cachefs
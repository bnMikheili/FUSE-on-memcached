#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define BUFF_LENGTH 1400

int get_cachefd();

void big_command(int cachefd, char *command, int key, int flag, int ttl, int size, char *data);

void command(int cachefd, char *command);

char *get(int cachefd, int key);

char *get_index_from_cache(int cachefd);

void index_init(int cachefd);

void incr_decr_command(int cachefd, char *command, char *key, int value);

void delete_command(int cachefd, int key);

void flush_all_command(int cachefd, size_t time);

char *inode_get(int cachefd, int parent_index, int index, int xattr);

void inode_big_command(int cachefd, char *command, int parent_index, int index, int size, char *data, int xattr);

void inode_delete_command(int cachefd, int parent_index, int index, int xattr);

int index_hash(const char *path, int size);

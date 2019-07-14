#include "memcache.h"

int get_cachefd()
{
    int cachefd = socket(AF_INET, SOCK_STREAM, 0);
    struct in_addr c_addr;
    inet_pton(AF_INET, "127.0.0.1", &c_addr.s_addr);
    struct sockaddr_in addr;
    addr.sin_addr = c_addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi("11211"));
    connect(cachefd, (const struct sockaddr *)&addr, sizeof(addr));
    return cachefd;
}

char *get(int cachefd, int key)
{
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "get %d\r\n", key);
    write(cachefd, command_str, strlen(command_str));
    char *response_buff = malloc(BUFF_LENGTH);
    read(cachefd, response_buff, BUFF_LENGTH);
    return response_buff;
}
void index_init(int cachefd)
{
    write(cachefd, "add INDEX 0 0 1\r\n1\r\n", strlen("add INDEX 0 0 1\r\n1\r\n"));
}

char *get_index_from_cache(int cachefd)
{
    write(cachefd, "get INDEX\r\n", strlen("get INDEX\r\n"));
    char *response_buff = malloc(BUFF_LENGTH);
    read(cachefd, response_buff, BUFF_LENGTH);
    close(cachefd);
}

void big_command(int cachefd, char *command, int key, int flag, int ttl, int size, char *data)
{
    char test_str[BUFF_LENGTH];
    sprintf(test_str, "%s %d %d %d %d\r\n", command, key, flag, ttl, size);
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "%s %d %d %d %d\r\n", command, key, flag, ttl, size);
    memcpy(command_str + strlen(test_str), data, size);
    command_str[size + strlen(test_str)] = '\r';
    command_str[size + strlen(test_str) + 1] = '\n';
    write(cachefd, command_str, strlen(test_str) + size + 2);
    char response_buff[1024];
    bzero(response_buff, 1024);
    read(cachefd, response_buff, 1024);
}

void command(int cachefd, char *command)
{
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "%s\r\n", command);
    write(cachefd, command_str, strlen(command_str));
    char response_buff[1024];
    bzero(response_buff, 1024);
    read(cachefd, response_buff, 1024);
}

void incr_decr_command(int cachefd, char *command, char *key, int value)
{
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "%s %s %d\r\n", command, key, value);
    write(cachefd, command_str, strlen(command_str));
    char response_buff[1024];
    read(cachefd, response_buff, 1024);
}

void delete_command(int cachefd, int key)
{
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "delete %d\r\n", key);
    write(cachefd, command_str, strlen(command_str));
    char response_buff[1024];
    bzero(response_buff, 1024);
    read(cachefd, response_buff, 1024);
}

void inode_big_command(int cachefd, char *command, int parent_index, int index, int size, char *data, int xattr)
{
    char sep = '~';
    if (xattr == 1)
        sep = '`';
    char test_str[BUFF_LENGTH];
    sprintf(test_str, "%s %d%c%d 0 0 %d\r\n", command, parent_index, sep, index, size);
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "%s %d%c%d 0 0 %d\r\n", command, parent_index, sep, index, size);
    memcpy(command_str + strlen(test_str), data, size);
    command_str[size + strlen(test_str)] = '\r';
    command_str[size + strlen(test_str) + 1] = '\n';
    write(cachefd, command_str, strlen(test_str) + size + 2);
    char response_buff[1024];
    bzero(response_buff, 1024);
    read(cachefd, response_buff, 1024);
}

char *inode_get(int cachefd, int parent_index, int index, int xattr)
{
    char sep = '~';
    if (xattr == 1)
        sep = '`';
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "get %d%c%d\r\n", parent_index, sep, index);
    write(cachefd, command_str, strlen(command_str));
    char *response_buff = malloc(BUFF_LENGTH);
    read(cachefd, response_buff, BUFF_LENGTH);
    return response_buff;
}
void inode_delete_command(int cachefd, int parent_index, int index, int xattr)
{
    char sep = '~';
    if (xattr == 1)
        sep = '`';
    char command_str[BUFF_LENGTH];
    sprintf(command_str, "delete %d%c%d\r\n", parent_index, sep, index);
    write(cachefd, command_str, strlen(command_str));
    char response_buff[1024];
    bzero(response_buff, 1024);
    read(cachefd, response_buff, 1024);
}

int index_hash(const char *path, int size)
{
    int i;
    int result = 0;
    for (i = 0; i < size; i++)
    {
        result = ((long long)path[i] + (long long)result * 293) % 1000000009;
    }
    return result;
}

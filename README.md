Design Document for: Fuse Memcached
==========================================

## Filesystem structure

### Files and directories

In this project one of the most important task was to find an optimal way for interacting with memcached, because unlike the disk, memcached saves information as a key:value pairs. Every single file and folder needs a unique key to give us an ability of saving them properly. The easiest way of getting those keys was using their own full pathes, but when we started implementation of the structure, there was not any regulation with the full path size, while the maximum memcached input was 250 and that was why I chose to have the hash number of the full path as a key. This approach was more than enough to guarantee the uniqueness of a key. In addition for making it simplier, I made the same structure abstraction for folders and files, there is just one flag **is_dir** for their differentiation. 

```c
    struct dir_struct
{
    int index;
    int is_dir;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int data_length;
    int xattr_length;
    int name_length;
    int is_symlink;
    char name[250];
};
 ```

Although the data is stored the same way for files and folders, we need to have the different approaches operating with them, becase the file's data is actual data and the folders data is files and folders. So for folders, I decided to store the indexes of files/folders owned by it. It gave us the ability to get access to the subdirectories and holding them as many as we want.

With the hash number as a key we can respond to the most of functions simultaniously, because for getting the file/directory structure takes just calculating the hash and getting response from memcached.

### Data 

When it came to storing data in memcached, I needed an effective way of storing it because a file can be big and we must have the ability to implement random access. For this purpose I decided to store the data chunks with pair of indexes: parent_index~index. So for each file/folder we have their own indexation of chunks. The parent index gives us uniqueness and the chunk index makes it possible to save as many chunks as **int** can count up to.

```c
    struct data
{
    int parent_index;
    int index;
    int length;
    char data[CHUNK_SIZE];
};
 ```

**parent_index** is the index of the owner file/folder, and the **index** is the chunk index of the data. This approach gives us ability to get the data chunk instantly for any data offset and therefore, the ability of **RANDOM ACCESS**. for ans offset we can easily calculate the chunk index in O(1) and send request to memcached for the data. Also, as long as we know the size of the data from the "dir_struct.data_length" variable, we can iterate on chunks and get the whole data if we need to. 

The maximum index of chunk depends on size of the data, but the size of int is greater than the number of chunks needed to store **1GB** data, so it won't make any problem. As we knew that the data is transfered along the TCP connection, which sends buckets with maximum size of 1500, I chose the "CHUNK_SIZE" to be 1024. 

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define STDIN_FD 0
#define STDOUT_FD 1

#include "threads/synch.h"

void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void close(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
int exec(const char *cmd_line);
int wait(int pid);

void syscall_init(void);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

#endif /* userprog/syscall.h */ 

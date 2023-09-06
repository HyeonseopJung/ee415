#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
/* close the file and update the file descriptor table */
/* add file to  file descriptor table */
int process_add_file(struct file *file_to_add);
/* get the file structure with fd */
struct file *process_get_file(int fd);
void process_close_file(int fd);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void argument_stack(char **argv, int argc, void **esp);
struct thread *get_child_process(int pid);
int remove_child_process(int pid);


#endif /* userprog/process.h */

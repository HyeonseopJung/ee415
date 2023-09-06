#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "../devices/shutdown.h"
#include "../filesys/filesys.h"
#include "../filesys/file.h"
#include "../threads/vaddr.h"
#include "../devices/input.h"
#include <string.h>
#include "process.h"
#include "pagedir.h"

#define MAX_ARGUMENT 128

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  lock_init(&file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int arg_list[MAX_ARGUMENT] = {0};
  check_address(f->esp);
  get_argument(f->esp, arg_list, 3);
  /* Check if address is in user address space */
  /* Get arguments into argument list */

  const char *file;
  int fd;
  char *buffer;
  unsigned int size;
  unsigned int position;

  uint32_t number = *(uint32_t *)(f->esp);
  switch (number)
  {
  case SYS_HALT: /* Halt the operating system. */
    halt();
    break;

  case SYS_EXIT: /* Terminate this process. */
    exit(arg_list[0]);
    break;

  case SYS_EXEC: /* Start another process. */
    f->eax = exec((const char *)arg_list[0]);
    break;

  case SYS_WAIT: /* Wait for a child process to die. */
    f->eax = wait((int)arg_list[0]);
    break;

  case SYS_CREATE:; /* Create a file. */
    file = (char *)arg_list[0];
    unsigned int initial_size = arg_list[1];
    f->eax = create(file, initial_size);
    break;

  case SYS_REMOVE:; /* Delete a file. */
    file = (char *)arg_list[0];
    f->eax = remove(file);
    break;

  case SYS_OPEN:; /* Open a file. */
    file = (char *)arg_list[0];
    f->eax = open(file);
    break;

  case SYS_FILESIZE:; /* Obtain a file's size. */
    fd = (int)arg_list[0];
    f->eax = filesize(fd);
    break;

  case SYS_READ:; /* Read from a file. */
    fd = (int)arg_list[0];
    buffer = (char *)arg_list[1];
    size = (unsigned int)arg_list[2];
    f->eax = (uint32_t)read(fd, buffer, size);
    break;

  case SYS_WRITE: /* Write to a file. */
    fd = (int)arg_list[0];
    buffer = (char *)arg_list[1];
    size = (unsigned int)arg_list[2];
    f->eax = write(fd, buffer, size);
    break;

  case SYS_SEEK: /* Change position in a file. */
    fd = arg_list[0];
    position = arg_list[1];
    seek(fd, position);
    break;

  case SYS_TELL: /* Report current position in a file. */
    fd = arg_list[0];
    f->eax = tell(arg_list[0]);
    break;

  case SYS_CLOSE: /* Close a file. */
    fd = arg_list[0];
    close(fd);
    break;

    /* exit the thread */
  default:
    thread_exit();
    break;
  }
}

/* implemented functions for Project 2 */

/* check if ADDR is within the user address space
 * if it's not (Kernel space), then must exit(-1)
 */
void check_address(void *addr)
{
  /* if user address is below the phys_base then check for pagefault*/
  struct thread *cur = thread_current();
  if (!is_user_vaddr(addr) || !pagedir_get_page(cur->pagedir, addr) || !addr)
  {
    exit(-1);
  }
}

/* Save the arguments in the user stack to the Kernel
 * Save COUNT number of data (bytes) in ESP to ARG
 */
void get_argument(void *esp, int *arg, int count)
{
  /* skip the number */
  esp = esp + 4;
  /* check if valid address every loop */
  int i;
  for (i = 0; i < count; i++, arg++)
  {
    char *walk = esp;
    /* check address only checks for address validation for single byte */
    /* must check for every byte (4 bytes per address) */
    int j;
    for (j = 0; j < 4; j++)
    {
      check_address(walk++);
    }
    *arg = *(uint32_t *)esp;
    esp = esp + 4;
  }
}

/* quit pintos */
void halt(void)
{
  shutdown_power_off();
}

/* end the current process
 * when exiting, print to stdout PROCESS_NAME: EXIT(STATUS)
 */
void exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;

  printf("%s: exit(%d)\n", cur->name, status);

  if (cur->parent != NULL)
  {
    sema_up(&(cur->parent->wait_children));
  }
  /* clear the file descriptor table */
  int fd;
  for (fd = 2; fd < FILE_DESCRIPTOR_MAX; fd++)
  {
    process_close_file(fd);
  }
  /* allow write */
  file_close(cur->running_file);
  sema_down(&cur->exit_sema);
  thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
  check_address(file);
  if (!file)
  {
    return false;
  }
  lock_acquire(&file_lock);
  if (filesys_create(file, initial_size))
  {
    lock_release(&file_lock);
    return true;
  }
  lock_release(&file_lock);
  return false;
}

bool remove(const char *file)
{
  if (!file)
  {
    return false;
  }
  check_address(file);
  lock_acquire(&file_lock);
  bool ret = filesys_remove(file);
  lock_release(&file_lock);
  return ret;
}

int open(const char *file)
{
  char *walk = file;
  int i;
  for (i = 0; i < 4; i++)
  {
    check_address(walk++);
  }

  int fd;
  struct file *file_to_open = filesys_open(file);

  if (!file_to_open)
  {
    return -1;
  }

  fd = process_add_file(file_to_open);

  if (fd == -1)
  {
    file_close(file_to_open);
  }
  return fd;
}

int filesize(int fd)
{
  struct file *file_to_get = process_get_file(fd);
  if (!file_to_get)
  {
    return -1;
  }
  return file_length(file_to_get);
}

int read(int fd, void *buffer, unsigned size)
{
  check_address(buffer);
  char *walk = (char *)buffer;
  int ret_count = 0;

  struct file *file_to_read;
  switch (fd)
  {
    /* if stdin count from the keyboard input */
  case STDIN_FD:;
    char key;
    lock_acquire(&file_lock);
    while ((unsigned int)ret_count < size)
    {
      key = input_getc();
      ret_count++;
      *walk = key;
      walk++;
      if (key == '\0')
      {
        break;
      }
    }
    lock_release(&file_lock);
    break;
    /* else if stdout return -1 */
  case STDOUT_FD:
    ret_count = -1;
    break;
    /* else */
  default:
    file_to_read = process_get_file(fd);
    if (!file_to_read)
    {
      ret_count = -1;
      break;
    }
    /* must lock the process so other process cannot access */
    lock_acquire(&file_lock);
    ret_count = file_read(file_to_read, buffer, size);
    /* must release lock so other process can read from file */
    lock_release(&file_lock);
    break;
  }
  return ret_count;
}

int write(int fd, void *buffer, unsigned size)
{
  check_address(buffer);
  int ret_count = 0;

  struct file *file_to_write;
  switch (fd)
  {
    /* if stdin count from the keyboard input */
  case STDIN_FD:
    ret_count = -1;
    break;
    /* else if stdout return -1 */
  case STDOUT_FD:
    putbuf(buffer, size);
    ret_count = size;
    break;
    /* else */
  default:
    file_to_write = process_get_file(fd);
    if (!file_to_write)
    {
      ret_count = -1;
      break;
    }

    lock_acquire(&file_lock);
    /* must lock the process so other process cannot access */
    ret_count = file_write(file_to_write, (const void *)buffer, size);
    /* must release lock so other process can read from file */
    lock_release(&file_lock);
    break;
  }
  return ret_count;
}

void close(int fd)
{
  struct file *file_to_close = process_get_file(fd);
  struct thread *cur = thread_current();

  if (fd < 2 || fd >= FILE_DESCRIPTOR_MAX)
  {
    return;
  }

  if (file_to_close)
  {
    lock_acquire(&file_lock);
    process_close_file(fd);
    //file_close(file_to_close);
    //cur->file_descriptor_table[fd] = NULL;
    lock_release(&file_lock);
  }
}

void seek(int fd, unsigned position)
{
  struct file *file_to_seek = process_get_file(fd);
  if (fd == 0 || fd == 1)
  {
    return;
  }
  if (file_to_seek)
  {
    file_seek(file_to_seek, position);
  }
}

unsigned tell(int fd)
{
  struct file *file_to_tell = process_get_file(fd);
  if (fd == 0 || fd == 1)
  {
    return 0;
  }
  unsigned int ret = 0;
  if (file_to_tell)
  {
    ret = file_tell(file_to_tell);
  }
  return ret;
}

int exec(const char *cmd_line) 
{
  char *walk = cmd_line;
  int i;
  for (i = 0; i < 4; i++)
  {
    check_address(walk++);
  }
  int child_tid = process_execute(cmd_line);
  return child_tid;
}

/* wait for child process with pid to exit and retrieve the exit status */
int wait(int pid)
{
  return process_wait(pid);
}
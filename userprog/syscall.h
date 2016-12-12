#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

typedef int pid_t;
struct lock file_semaphore;

void sys_exit (int status);
int sys_halt(void);
int sys_create (const char *file, unsigned initial_size);
int sys_open (const char *file);
void sys_close (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
int sys_filesize (int fd);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
int sys_remove (const char *file);

void load_pt(int fd, void* buffer, unsigned size, void* esp);

void syscall_init (void);
void unpin(void* addr);

struct proc_file{
	struct list_elem elem;
	int fd;
	struct file *file;
	struct dir* dir;
};

#endif /* userprog/syscall.h */

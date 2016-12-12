#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "vm/page_table.h"
#include "vm/frame_table.h"




static void syscall_handler (struct intr_frame *);



typedef int (*handler) (uint32_t, uint32_t, uint32_t);
handler syscall_pointer[128];


int check_ptr(const void *vaddr);
enum fd_search_filter {FD_FILE = 1, FD_DIRECTORY = 2};
struct proc_file* get_file_struct(int fd, enum fd_search_filter flag);



//uint32_t* esp;

bool sys_chdir(const char* filename);
bool sys_mkdir(const char* filename);
bool sys_readdir(int fd, char* filename);
bool sys_isdir(int fd);
int sys_inumber(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscall_pointer[SYS_EXIT] = (handler)sys_exit;
  syscall_pointer[SYS_HALT] = (handler)sys_halt;
  syscall_pointer[SYS_CREATE] = (handler)sys_create;
  syscall_pointer[SYS_OPEN] = (handler)sys_open;
  syscall_pointer[SYS_CLOSE] = (handler)sys_close;
  syscall_pointer[SYS_READ] = (handler)sys_read;
  syscall_pointer[SYS_WRITE] = (handler)sys_write;
  syscall_pointer[SYS_EXEC] = (handler)sys_exec;
  syscall_pointer[SYS_WAIT] = (handler)sys_wait;
  syscall_pointer[SYS_FILESIZE] = (handler)sys_filesize;
  syscall_pointer[SYS_SEEK] = (handler)sys_seek;
  syscall_pointer[SYS_TELL] = (handler)sys_tell;
  syscall_pointer[SYS_REMOVE] = (handler)sys_remove;
	syscall_pointer[SYS_CHDIR] = (handler)sys_chdir;
	syscall_pointer[SYS_MKDIR] = (handler)sys_mkdir;
	syscall_pointer[SYS_READDIR] = (handler)sys_readdir;
	syscall_pointer[SYS_ISDIR] = (handler)sys_isdir;
	syscall_pointer[SYS_INUMBER] = (handler)sys_inumber;

	lock_init(&file_semaphore);
}

static void
syscall_handler (struct intr_frame *f) 
{
  handler h;
	check_ptr((const void*)f->esp);
  int* call = f->esp;
	//esp = f->esp;
	int k;	
	int call_type = (int)*call;
	//printf("syscall, %d %d\n", call_type, thread_current()->tid);
	//if (call_type == 8){
		//printf("esp %d %d %d\n", esp, *esp, thread_current()->tid); 
	//}
	switch(call_type)
	{
		case SYS_HALT:
		{
			check_ptr((const void*)f->esp);
		}
		case SYS_EXIT:
		case SYS_EXEC:
		case SYS_WAIT:
		case SYS_REMOVE:
		case SYS_OPEN:
		case SYS_FILESIZE:
		case SYS_TELL:
		case SYS_CLOSE:
		case SYS_CHDIR:
		case SYS_MKDIR:
		case SYS_ISDIR:
		case SYS_INUMBER:
		{	
			for (k = 0; k < 1; k += 1)
			{
				check_ptr((const void*)f->esp + (k * 4));
			}
		}
		case SYS_CREATE:
		case SYS_SEEK:
		case SYS_READDIR:
		{
			for (k = 0; k < 2; k += 1)
			{
				check_ptr((const void*)f->esp + (k * 4));
			}
		}
		case SYS_READ:
		case SYS_WRITE:
		{
			for (k = 0; k < 3; k += 1)
			{
				check_ptr((const void*)f->esp + (k * 4));
			}
		}
	}
	//load pages
	if (call_type == SYS_READ || call_type == SYS_WRITE){
		load_pt(*(call + 1), *(call + 2), *(call + 3), f->esp);
	}
  if (!(is_user_vaddr(call) && is_user_vaddr(call+1) && is_user_vaddr(call+2) 
	  && is_user_vaddr(call+3)) || *call > SYS_INUMBER || *call < SYS_HALT)
    thread_exit();
  h = syscall_pointer[*call];
	
  f->eax = h(*(call+1), *(call+2), *(call+3));
	unpin(f->esp);
  return;
}



void load_pt(int fd, void* buffer, unsigned size, void* esp){
	if (fd == STDOUT_FILENO || fd == STDIN_FILENO){
		return;
	}
	int k;
	void* buffer_check = buffer;
	struct page_table_entry* pt2;
	void* page2;
	//actual file
	if (buffer < 0x08048000 || !is_user_vaddr(buffer) 
		|| buffer + size < 0x08048000 || !is_user_vaddr(buffer + size)){
		//printf("bad addr %d\n", thread_current()->tid);
		sys_exit(-1);
	}
	//printf("espcheck2 read %d\n", esp);
	for (k = 0; k < size; k += 1)
	{
		buffer_check = buffer + k;
		
		//check_ptr((void*)buffer_check);
		if (buffer_check == NULL || buffer_check < 0x08048000 || !is_user_vaddr(buffer_check))
    {
			//printf("bad addr2 %d\n", thread_current()->tid);
      sys_exit(-1);
    }
		int success;
		//printf("test1\n");
		//printf("reading page %x\n", buffer_check);
		struct page_table_entry* pt = pt_lookup((void*)buffer_check);
		void* page_buffer = pg_round_down((void*)buffer_check);
		//printf("what %d %d\n", buffer_check, page_buffer);
		//printf("pt is %x\n", pt->addr);
		//printf("test2\n");
		//esp2 = (int*)esp;
		//espi = *esp2;
		//printf("espcheck3 read %d %d\n", esp2, espi);
		if (pt == NULL && buffer_check >= (esp - 32)){
			//printf("read grow %d %d\n", thread_current()->tid, page_buffer);
			// && (PHYS_BASE - pg_round_down(fault_addr)) <= STACK_SIZE
			success = grow_stack(buffer_check);
			if(success == 0){
				//printf("no grow stack %d\n", thread_current()->tid);
				sys_exit(-1);
			}
		}
		//printf("espcheck3 read %d\n", esp);
		if(pt == NULL && buffer_check < (esp - 32)){
			//printf("no pt addr wrong %d %d %d %d %d\n", thread_current()->tid, esp, buffer_check, buffer, buffer + size);
			sys_exit(-1);
		}
		if (pt != NULL && pt->loaded){
			//printf("already loaded %d %d %d\n", thread_current()->tid, page_buffer, pt->type, buffer_check);
		}
		
		if(pt != NULL && !pt->loaded){
			//printf("page\n");
			pt->pinned = 1;
			//check write permissions
			if (!pt->write){
				//printf("can't write %d\n", thread_current()->tid);

				sys_exit(-1);
			}
			//printf("before frame\n");
			uint8_t* frame;
			enum palloc_flags flags = PAL_USER;
			if (pt->type == 0 && pt->bytes_zero == PGSIZE){
				flags |= PAL_ZERO;
			} 
			frame = get_frame(flags);
			//printf("after page\n");
			if (frame == NULL){
				//printf("no frame %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			//link frame to page table
			struct frame_table_entry* ft = ft_lookup(frame);
			//if (ft != NULL){
				ft->pt = pt;
			//}
			//printf("after ft_lookup %d\n", pt->loaded);
			//printf("possible fetch read %d %d %d\n",thread_current()->tid, pt->addr, frame);
			page_fetch(frame, pt);
			//page_fetch(pt);
			//printf("after fetch\n");
			success = pt->loaded;
			
			if (success == 0){
				//printf("read not loaded %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			if (pt->type != 1){
		success = pagedir_set_page(pt->pagedir, pt->addr, frame, (bool)pt->write);
			//pagedir_set_dirty(pt->pagedir, pt->addr, false);
			//pagedir_set_accessed(pt->pagedir, pt->addr, true);
			}
			
			//pt->pinned = 0;
			//printf("after all\n");
			if(success == 0){
				//printf("no set page %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			pt2 = pt;
			page2 = frame;
		}
		
	}
}
/*
 Terminates Pintos by calling shutdown_power_off() (declared in threads/init.h).
 This should be seldom used, because you lose some information about possible deadlock situations, etc.
*/
int
sys_halt (void)
{
  shutdown_power_off();
}

/* 
 Terminates the current user program, returning status to the kernel. 
 If the process's parent waits for it (see below), this is the status that will be returned. 
 Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
void
sys_exit (int status)
{
  struct thread *current_thread;
	current_thread = thread_current();
	if (current_thread->child && thread_running(current_thread->parent))
	{
		current_thread->child->status = status;
	}
	//printf("exit %d\n", current_thread->tid);
	printf("%s: exit(%d)\n",current_thread->name, status);
  thread_exit();
}

/*
 Runs the executable whose name is given in cmd_line, passing any given arguments, 
 and returns the new process's program id (pid). 
 Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason.
 Thus, the parent process cannot return from the exec until it knows whether the
 child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
*/
pid_t 
sys_exec (const char *cmd_line)
{
	int cmd_line_convert;
	check_ptr(cmd_line);
	struct child* child;
	struct thread* this_thread;
	struct list_elem *e;
	pid_t pid;
	//cmd_line_convert = convert_ptr((const void *) cmd_line); 
	//pid = process_execute((const char*) cmd_line_convert);
	pid = process_execute(cmd_line);
	if (pid == -1)
	{
		return -1;
	}
	this_thread = thread_current();
	for (e = list_begin(&this_thread->child_list); e != list_end(&this_thread->child_list); e = list_next(e))
	{
		child = list_entry(e, struct child, elem);
		if (pid == child->pid)
		{
			break;
		}
	}
	if(child->load_status == 0){
		dec_load_s(child);
	}
	if(child->load_status == -1){
		list_remove(&child->elem);
		free(child);
		return -1;
	}
	return pid;
}

/*
 Waits for a child process pid and retrieves the child's exit status.
 If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. 
 If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), 
 wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes 
 that have already terminated by the time the parent calls wait, but the kernel must still allow 
 the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

 wait must fail and return -1 immediately if any of the following conditions is true:

 pid does not refer to a direct child of the calling process. 
 pid is a direct child of the calling process if and only if the calling process 
 received pid as a return value from a successful call to exec.
 Note that children are not inherited: if A spawns child B and B spawns child process C, 
 then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. 
 Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.

 The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.
 Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children. 
 Your design should consider all the ways in which waits can occur. 
 All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, 
 and regardless of whether the child exits before or after its parent.

 You must ensure that Pintos does not terminate until the initial process exits. 
 The supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main() (in threads/init.c). 
 We suggest that you implement process_wait() according to the comment at the top of the function and then implement the wait system call in terms of process_wait().

 Implementing this system call requires considerably more work than any of the rest.
*/
int
sys_wait (pid_t pid)
{
  return process_wait(pid);
}

/*
 Creates a new file called file initially initial_size bytes in size. Returns true if successful, false otherwise. 
 Creating a new file does not open it: opening the new file is a separate operation which would require a open system call.
*/
int
sys_create (const char *file, unsigned initial_size)
{
	//int file_convert = convert_ptr((const void*) file);  
	//file = (const char*)file_convert;
	check_ptr(file);
	//printf("create\n");
	lock_acquire(&file_semaphore);
	if (strlen(file) > 14){
		lock_release(&file_semaphore);
		return 0;
	}
	bool file_created = filesys_create(file, initial_size, false);
	lock_release(&file_semaphore);
	//printf("create release\n");
	return file_created;
}

/*
 Deletes the file called file. Returns true if successful, false otherwise. 
 A file may be removed regardless of whether it is open or closed, and removing an open file does not close it. 
 See Removing an Open File, for details.
*/
int 
sys_remove (const char *file)
{
	//int file_convert = convert_ptr((const void*) file);  
	//file = (const char*)file_convert;
	check_ptr(file);
	//printf("remove\n");
	lock_acquire(&file_semaphore);
  bool file_removed = filesys_remove(file);
	lock_release(&file_semaphore);
	//printf("remove releas\n");
	return file_removed;
}

/*
 Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd), or -1 if the file could not be opened.
 File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard output. 
 The open system call will never return either of these file descriptors, which are valid as system call arguments only as explicitly described below.

 Each process has an independent set of file descriptors. File descriptors are not inherited by child processes.

 When a single file is opened more than once, whether by a single process or different processes, each open returns a new file descriptor. 
 Different file descriptors for a single file are closed independently in separate calls to close and they do not share a file position.
*/
int 
sys_open (const char *file)
{
	//int file_convert = convert_ptr((const void*) file);  
	//file = (const char*)file_convert;
	check_ptr(file);
	//printf("open\n");
  lock_acquire(&file_semaphore);
	struct file* fileOpen = filesys_open(file);
	if (!fileOpen){
		lock_release(&file_semaphore);
		//printf("opn release\n");
		return -1;
	}
	//add file to list
	struct proc_file* add_file = malloc(sizeof(struct proc_file));
	if (!add_file)
	{
		lock_release(&file_semaphore);
		return -1;
	}
	add_file->file = fileOpen;

	//directory
	struct inode* inode = file_get_inode(add_file->file);
	if(inode != NULL && inode_is_directory(inode)){
		add_file->dir = dir_open(inode_reopen(inode));
	}
	else{
		add_file->dir = NULL;
	}

	add_file->fd = thread_current()->fd;	
	//fd goes up
	thread_current()->fd += 1;
	list_push_back(&thread_current()->file_list, &add_file->elem);
	lock_release(&file_semaphore);
	//printf("open relase\n");
	return add_file->fd;
}

/* 
 Returns the size, in bytes, of the file open as fd.
*/
int 
sys_filesize (int fd)
{
	//printf("filesize\n");
	lock_acquire(&file_semaphore);
	struct file* countFile = get_file_struct(fd, FD_FILE)->file;
	if (!countFile){
		lock_release(&file_semaphore);
		//printf("filesize release\n");
		return -1;
	}
	int file_size = file_length(countFile);
	lock_release(&file_semaphore);
	//printf("filesize release\n");
	return file_size;
}


/*
 Reads size bytes from the file open as fd into buffer. 
 Returns the number of bytes actually read (0 at end of file), 
 or -1 if the file could not be read (due to a condition other than end of file). 
 Fd 0 reads from the keyboard using input_getc().
*/
int 
sys_read (int fd, void *buffer, unsigned size)
{
	//printf("espcheck read %d\n", esp);
	//printf("read\n");
	int k;
	void* buffer_check = buffer;
	if (fd == STDOUT_FILENO){
		//printf("not possible\n");
		sys_exit(-1);
	}
	if (fd == STDIN_FILENO){
		for (k = 0; k < size; k += 1)
		{
			check_ptr((void*)buffer_check + k);
		}
		char* handler_buffer = (char*) buffer;
		int i;
		for (i = 0; i < size; i += 1){
			handler_buffer[i] = input_getc();
		}
		return size;
	}
	/*struct page_table_entry* pt2;
	void* page2;
	//actual file
	if (buffer < 0x08048000 || !is_user_vaddr(buffer) 
		|| buffer + size < 0x08048000 || !is_user_vaddr(buffer + size)){
		printf("bad addr %d\n", thread_current()->tid);
		sys_exit(-1);
	}
	printf("espcheck2 read %d\n", esp);
	for (k = 0; k < size; k += 1)
	{
		buffer_check = buffer + k;
		
		//check_ptr((void*)buffer_check);
		if (buffer_check == NULL || buffer_check < 0x08048000 || !is_user_vaddr(buffer_check))
    {
			printf("bad addr2 %d\n", thread_current()->tid);
      sys_exit(-1);
    }
		int success;
		//printf("test1\n");
		//printf("reading page %x\n", buffer_check);
		struct page_table_entry* pt = pt_lookup((void*)buffer_check);
		void* page_buffer = pg_round_down((void*)buffer_check);
		//printf("what %d %d\n", buffer_check, page_buffer);
		//printf("pt is %x\n", pt->addr);
		//printf("test2\n");
		//esp2 = (int*)esp;
		//espi = *esp2;
		//printf("espcheck3 read %d %d\n", esp2, espi);
		if (pt == NULL && buffer_check >= (esp - 32)){
			printf("read grow %d %d\n", thread_current()->tid, page_buffer);
			// && (PHYS_BASE - pg_round_down(fault_addr)) <= STACK_SIZE
			success = grow_stack(buffer_check);
			if(success == 0){
				printf("no grow stack %d\n", thread_current()->tid);
				sys_exit(-1);
			}
		}
		printf("espcheck3 read %d\n", esp);
		if(pt == NULL && buffer_check < (esp - 32)){
			printf("no pt addr wrong %d %d %d %d %d\n", thread_current()->tid, esp, buffer_check, buffer, buffer + size);
			sys_exit(-1);
		}
		if (pt != NULL && pt->loaded){
			//printf("already loaded %d %d %d\n", thread_current()->tid, page_buffer, pt->type, buffer_check);
		}
		
		if(pt != NULL && !pt->loaded){
			//printf("page\n");
			pt->pinned = 1;
			//check write permissions
			if (!pt->write){
				printf("can't write %d\n", thread_current()->tid);

				sys_exit(-1);
			}
			//printf("before frame\n");
			uint8_t* frame;
			enum palloc_flags flags = PAL_USER;
			if (pt->type == 0 && pt->bytes_zero == PGSIZE){
				flags |= PAL_ZERO;
			} 
			frame = get_frame(flags);
			//printf("after page\n");
			if (frame == NULL){
				printf("no frame %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			//link frame to page table
			struct frame_table_entry* ft = ft_lookup(frame);
			//if (ft != NULL){
				ft->pt = pt;
			//}
			//printf("after ft_lookup %d\n", pt->loaded);
			//printf("possible fetch read %d %d %d\n",thread_current()->tid, pt->addr, frame);
			page_fetch(frame, pt);
			//page_fetch(pt);
			//printf("after fetch\n");
			success = pt->loaded;
			
			if (success == 0){
				printf("read not loaded %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			if (pt->type != 1){
		success = pagedir_set_page(pt->pagedir, pt->addr, frame, (bool)pt->write);
			//pagedir_set_dirty(pt->pagedir, pt->addr, false);
			//pagedir_set_accessed(pt->pagedir, pt->addr, true);
			}
			
			//pt->pinned = 0;
			//printf("after all\n");
			if(success == 0){
				printf("no set page %d\n", thread_current()->tid);
				sys_exit(-1);
			}
			pt2 = pt;
			page2 = frame;
		}
		
	}*/
	//int buffer_convert = convert_ptr((const void*) buffer);  
	//buffer = (void*)buffer_convert;
	//printf("read %d %d %d %d %d %d\n", thread_current()->tid, pt2->addr, buffer, buffer + size, page2, buffer_check);
	lock_acquire(&file_semaphore);
	struct proc_file* read_file = get_file_struct(fd, FD_FILE);
	if (read_file == NULL){
		//printf("read release\n");
		lock_release(&file_semaphore);
		buffer_check = buffer;
		for (k = 0; k < size; k += 1)
		{
			unpin(buffer_check + k);
		}
		return -1;
	}
	int count = file_read(read_file->file, buffer, size);
	lock_release(&file_semaphore);
	//printf("read release\n");
	buffer_check = buffer;
	for (k = 0; k < size; k += 1)
	{
		unpin(buffer_check + k);
	}

	return count;
}

/*
 Writes size bytes from buffer to the open file fd. 
 Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
 Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. 
 The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

 Fd 1 writes to the console. 
 Your code to write to the console should write all of buffer in one call to putbuf(), 
 at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) 
 Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.
*/
int 
sys_write (int fd, const void *buffer, unsigned size)
{
	//printf("write\n");
	int k;
	void* buffer_check = buffer;
	if (fd == STDIN_FILENO){
		sys_exit(-1);
	}
	if (fd == STDOUT_FILENO)
  {
	//printf("stdout\n");
	for (k = 0; k < size; k += 1){
		//printf("what1 %x\n", buffer_check + k);
		check_ptr((void*)buffer_check + k);
	}
      //max size?
			//printf("after check\n");
      putbuf(buffer, size);
			//printf("after putbuf\n");
			//printf("stdout done\n");
      return size;
  } 
	//printf("not stdout\n");
	/*if (buffer < 0x08048000 || !is_user_vaddr(buffer) 
		|| buffer + size < 0x08048000 || !is_user_vaddr(buffer + size)){
		sys_exit(-1);
	}
	for (k = 0; k < size; k += 1)
	{
		
		buffer_check = buffer + k;
		//check_ptr((void*)buffer_check);
		if (buffer_check == NULL || buffer_check < 0x08048000 || !is_user_vaddr(buffer_check))
    {
      sys_exit(-1);
    }
		int success;
		struct page_table_entry* pt = pt_lookup((void*)buffer_check);
		if (pt == NULL && buffer_check >= (esp - 32)){
			// && (PHYS_BASE - pg_round_down(fault_addr)) <= STACK_SIZE
			//printf("write grow\n");
			success = grow_stack(buffer_check);
			if(success == 0){
				sys_exit(-1);
			}
		}
		if(pt == NULL && buffer_check < (esp - 32)){
			sys_exit(-1);
		}
		if(pt != NULL && !pt->loaded){
			pt->pinned = 1;
			//printf("not grow\n");
			//check write permissions?
			uint8_t* frame;
			enum palloc_flags flags = PAL_USER;
			if (pt->type == 0 && pt->bytes_zero == PGSIZE){
				flags |= PAL_ZERO;
			} 
			frame = get_frame(flags);
			if (frame == NULL){
				sys_exit(-1);
			}
			//link frame to page table
			struct frame_table_entry* ft = ft_lookup(frame);
			//if (ft != NULL){
				ft->pt = pt;
			//}
			//printf("possible fetch write %d\n", pt->addr);
			page_fetch(frame, pt);
			//page_fetch(pt);
			success = pt->loaded;
			if (success == 0){
				//printf("write not loaded\n");
				sys_exit(-1);
			}
			if (pt->type != 1){
		success = pagedir_set_page(pt->pagedir, pt->addr, frame, (bool)pt->write);
			//pagedir_set_dirty(pt->pagedir, pt->addr, false);
			//pagedir_set_accessed(pt->pagedir, pt->addr, true);
			}
			
			//pt->pinned = 0;
			if(success == 0){
				//printf("write last\n");
				sys_exit(-1);
			}
		}
		
	}*/
	//printf("after\n");
	//int buffer_convert = convert_ptr((const void*) buffer);  
	//buffer = (void*)buffer_convert;
  		//printf("write\n");
			lock_acquire(&file_semaphore);
			struct proc_file* write_file = get_file_struct(fd, FD_FILE);
			if (write_file == NULL){
				lock_release(&file_semaphore);
				//printf("write release\n");
				buffer_check = buffer;
				for (k = 0; k < size; k += 1)
				{
					unpin(buffer_check + k);
				}
				return -1;
			}
			int count = file_write(write_file->file, buffer, size);
			lock_release(&file_semaphore);
			//printf("write release\n");
			
 			buffer_check = buffer;
			for (k = 0; k < size; k += 1)
			{
				unpin(buffer_check + k);
			}
		//printf("write afet 2\n");
		return count;
}

/*
 Changes the next byte to be read or written in open file fd to position, 
 expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
 A seek past the current end of a file is not an error. 
 A later read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros. 
 (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) 
 These semantics are implemented in the file system and do not require any special effort in system call implementation.
*/
void 
sys_seek (int fd, unsigned position)
{
	//printf("seek\n");
	lock_acquire(&file_semaphore);
	struct proc_file* seek_file = get_file_struct(fd, FD_FILE);
	if (seek_file == NULL){
		lock_release(&file_semaphore);
			//printf("seek release\n");
		return;
	}
	file_seek(seek_file->file, position);
	lock_release(&file_semaphore);
	//printf("seek release\n");
}

/*
 Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
*/
unsigned 
sys_tell (int fd)
{
	//printf("tell\n");
	lock_acquire(&file_semaphore);
	struct proc_file* tell_file = get_file_struct(fd, FD_FILE);
	if (tell_file == NULL){
		lock_release(&file_semaphore);
		//printf("tell relase\n");
		return;
	}
	off_t offset = file_tell(tell_file->file);
	lock_release(&file_semaphore);
	//printf("tell relase\n");
	return offset;
}

/*
 Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file descriptors, as if by calling this function for each one.
*/
void 
sys_close (int fd)
{
	//printf("close\n");
	lock_acquire(&file_semaphore);
	struct proc_file* close_file = get_file_struct(fd, FD_FILE | FD_DIRECTORY);
	if (close_file != NULL){
			file_close(close_file->file);
			if (close_file->dir != NULL){
				dir_close(close_file->dir);
			}
			list_remove(&close_file->elem);
			free(close_file);
	}	
	lock_release(&file_semaphore);
	//printf("close relsase\n");
	return;
}

bool sys_chdir(const char* filename){
	bool return_code;
	
	lock_acquire(&file_semaphore);
	return_code = filesys_chdir(filename);
	lock_release(&file_semaphore);
	return return_code;
}

bool sys_mkdir(const char* filename){
	bool return_code;
	
	lock_acquire(&file_semaphore);
	return_code = filesys_create(filename, 0, true);
	lock_release(&file_semaphore);
	return return_code;
}

bool sys_readdir(int fd, char* filename){
	struct proc_file* file_d;
	bool ret = false;

	lock_acquire(&file_semaphore);
	file_d = get_file_struct(fd, FD_DIRECTORY);
	if (file_d == NULL){
		lock_release(&file_semaphore);	
		return false;
	}
	struct inode* inode;
	inode = file_get_inode(file_d->file);
	if (inode == NULL){
		lock_release(&file_semaphore);
		return false;
	}
	if (!inode_is_directory(inode)){
		lock_release(&file_semaphore);
		return false;
	}
	ASSERT(file_d->dir != NULL);
	ret = dir_readdir(file_d->dir, filename);
	lock_release(&file_semaphore);
	return ret;
}

bool sys_isdir(int fd){
	struct proc_file* file_d;
	bool ret;
	lock_acquire(&file_semaphore);
	file_d = get_file_struct(fd, FD_FILE | FD_DIRECTORY);
	ret = inode_is_directory(file_get_inode(file_d->file));
	lock_release(&file_semaphore);
	return ret;
}

int sys_inumber(int fd){
	struct proc_file* file_d;
	int ret;
	lock_acquire(&file_semaphore);
	file_d = get_file_struct(fd, FD_FILE | FD_DIRECTORY);
	ret = (int) inode_get_inumber(file_get_inode(file_d->file));
	lock_release(&file_semaphore);
	return ret;
}



//null, unmapped virtual memory (< 0x08048000), above PHYS_BASE
int 
check_ptr(const void *vaddr)
{
  if (vaddr == NULL || vaddr < 0x08048000 || !is_user_vaddr(vaddr))
    {
			//printf("bad ptr\n");
      sys_exit(-1);
    }
	//unmapped
	void* mapped = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!mapped)
	{
		//printf("not mapped\n");
		sys_exit(-1);
	}
}

int convert_ptr(const void *vaddr)
{
	check_ptr(vaddr);
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	if (!ptr)
	{
		sys_exit(-1);
	}
	return (int) ptr;
}


struct proc_file* get_file_struct(int fd, enum fd_search_filter flag)
{
	struct thread* current_thread = thread_current();
	struct list_elem* e;
	struct list* file_list = &current_thread->file_list;
	for (e = list_begin(file_list); e != list_end(file_list); e = list_next(e))
	{
		struct proc_file *current_file = list_entry(e, struct proc_file, elem);
		if (current_file->fd == fd){
			if (current_file->dir != NULL && (flag & FD_DIRECTORY)){
				return current_file;
			}
			else if (current_file->dir == NULL && (flag & FD_FILE)){
				return current_file;
			}
			
		}
	}
	return NULL;
}

void unpin(void* addr){
	struct page_table_entry* pt = pt_lookup(addr);
	if(pt != NULL){
		pt->pinned = 0;
	}
}




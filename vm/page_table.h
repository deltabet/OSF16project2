#include <hash.h>
#include "threads/synch.h"
#include "userprog/process.h"

#define MAX_STACK_SIZE (1 << 23)

//struct lock pt_lock;

struct page_table_entry{
	struct hash_elem hash_elem;
	void* addr; //virtual address
	int write;
	int type;
	//0 is file, 1 is switch
	int* pagedir; //hardware pagedir, set to current_thread->pagedir

	struct file* file;
	int offset;
	int bytes_read;
	int bytes_zero;

	//swap
	size_t swap_ind;
	//load
	int loaded;
	//pin
	int pinned;
};

void page_table_init(void);
struct page_table_entry* pt_lookup(void* addr);
int page_fetch(void* page, struct page_table_entry* pt);
//int page_fetch(struct page_table_entry* pt);
int pt_add_file(uint8_t* upage, struct file* file, int32_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
void remove_page_table(void);
int grow_stack(void* addr);


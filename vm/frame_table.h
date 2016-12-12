#include <lib/kernel/hash.h>
#include "threads/synch.h"
#include "threads/palloc.h"

struct lock ft_lock;

struct hash ft_hash;
//for clock algorithm
struct list ft_list;

struct frame_table_entry{
	void* page;
	struct hash_elem hash_elem;
	struct list_elem list_elem;
	struct thread *thread;
	uint32_t* pte;
	//pagedir of owning thread
	uint32_t* pagedir;
	//page table
	struct page_table_entry* pt;
	int loaded;
};

void frame_table_init(void);
void frame_table_init0(void);
void* get_frame(enum palloc_flags flags);
void free_frame(void *ft);
struct frame_table_entry* ft_lookup(void* page);
void evict(void);
//void* evict(enum palloc_flags flags);



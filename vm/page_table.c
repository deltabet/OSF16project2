#include "vm/page_table.h"
#include "vm/frame_table.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include <string.h>



unsigned pt_get_hash(const struct hash_elem *p_, void *aux UNUSED){
	const struct page_table_entry *p = hash_entry(p_, struct page_table_entry, hash_elem);
	return hash_int((unsigned)p->addr);
}

bool pt_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
	const struct page_table_entry *a = hash_entry(a_, struct page_table_entry, hash_elem);
	const struct page_table_entry *b = hash_entry(b_, struct page_table_entry, hash_elem);
	return a->addr < b->addr;
}

void page_table_init(void){
	//lock_init(&pt_lock);
	bool succ = hash_init(&thread_current()->page_table, pt_get_hash, pt_less, NULL);
}

struct page_table_entry* pt_lookup(void* addr){
	struct page_table_entry pt;
	struct hash_elem *e;
	addr = pg_round_down(addr);
	pt.addr = addr;
	e = hash_find(&thread_current()->page_table, &pt.hash_elem);
	return e != NULL ? hash_entry(e, struct page_table_entry, hash_elem) : NULL;
}

int page_fetch(void* page, struct page_table_entry* pt){
//int page_fetch(struct page_table_entry* pt){
	//printf("pinned status %d\n", pt->pinned);
	//pt->pinned = 1;
	//uint8_t* page = get_frame(PAL_USER);
	//struct frame_table_entry* ft = ft_lookup(page);
	//ft->pt = pt;
	//printf("fetch\n");
	if(pt->loaded == 1){
		//printf("already loaded\n");
		return 0;
	}
	if (pt->type == 0){
		//printf("file%x %d\n", pt->addr, thread_current()->tid);
		//bool success = pagedir_set_page(pt->pagedir, pt->addr, page, (bool)pt->write);
			//if (!success)
      //{
				//printf("file set pagedir fail\n");
        //free_frame(page);
        //return false;
      //}
		//if (pt->bytes_zero == PGSIZE){
			//set all to 0
			//printf("zeros\n");
			//memset(page, 0, PGSIZE);
		//}
		//else{
			//load
			//printf("before file read %d %d %d\n", thread_current()->tid, pt->addr, page);
			lock_acquire(&file_semaphore);
			//printf("after file read %d %d %d\n", thread_current()->tid, pt->addr, page);
			if (file_read_at(pt->file, page, pt->bytes_read, pt->offset) != (int) pt->bytes_read){
				free_frame(page);
				
				lock_release(&file_semaphore);
				//printf("file fail release lock %d %d %d\n", thread_current()->tid, pt->addr, page);
				return 0;
			}
			//set rest to 0
			
			lock_release(&file_semaphore);
			//printf("file succ release lock %d %d %d\n", thread_current()->tid, pt->addr, page);
			memset(page + pt->bytes_read, 0, pt->bytes_zero);
			//add page to process address space
			//install_page already done in page fault
			
			//if (!install_page(pt->addr, page, pt->write))
			
			
		//}
	}
	if (pt->type == 1){
		//printf("swap %d %d\n", pt->addr, thread_current()->tid);
		//swap
		/*uint8_t* kpage = get_frame(PAL_USER);
		if(!kpage){
			return 0;
		}
		//map, set pt of frame
		struct frame_table_entry* ft = ft_lookup(kpage);
		if (ft != NULL){
			ft->pt = pt;
		}	*/
		//install page already done
		//printf("pagedir %x %x\n", thread_current()->pagedir, pt->pagedir);
		bool success = pagedir_set_page(pt->pagedir, pt->addr, page, (bool)pt->write);
		//bool success = install_page(pt->addr, page, pt->write);
		//printf("swap page before dirty\n");
		if(!success){
			//printf("swap pagedir set page fail\n");
			free_frame(page);
			return 0;
		}
		swap_in(pt->swap_ind, pt->addr);
		//printf("swap in done at page %d\n", pt->addr);
		//printf("addr: %d\n", pt->addr);
		//printf("pagedir: %d\n", pt->pagedir);
		//printf("swap_ind: %d\n", pt->swap_ind);
		//printf("load: %d\n", pt->loaded);
		//printf("ft->pt, %d\n", ft->pt);
		//printf("ft->page, %d %d\n", ft->page, page);
		//printf("ft thread%d\n", ft->thread->tid);
		//printf("ft pte %d\n", ft->pte);
		//printf("ft pagedir %d\n", ft->pagedir);
		
	}
	
	pt->loaded = 1;
	//if (pt->addr == 134578176){
		//printf("xxx %d %d %d\n",thread_current()->tid, pt->type, pt->loaded);
	//}
	//pt->pinned = 0;
	
	return 1;
}

int pt_add_file(uint8_t* upage, struct file* file, int offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
	//printf("add file page\n");
	struct page_table_entry *pt = malloc(sizeof(struct page_table_entry));
	if (pt == NULL){
		return 0;
	}
	pt->addr = upage;
	//printf("add file addr %d\n", pt->addr);
	pt->file = file;
	pt->offset = offset;
	pt->bytes_read = read_bytes;
	pt->bytes_zero = zero_bytes;
	//printf("new file %x\n", pt->addr);
	pt->type = 0;
	pt->write = writable;
	pt->pagedir = thread_current()->pagedir;
	pt->pinned = 0;
	pt->loaded = 0;

	struct hash_elem * success = hash_insert(&thread_current()->page_table, &pt->hash_elem);
	if (success != NULL){
		free(pt);
		return 0;
	}
	return 1;
}

void pt_destroy(struct hash_elem *d, void* aux UNUSED){
	struct page_table_entry* pt = hash_entry(d, struct page_table_entry, hash_elem);
	if(pt->loaded){
		free_frame(pagedir_get_page(thread_current()->pagedir, pt->addr));
		pagedir_clear_page(thread_current()->pagedir, pt->addr);
	}
	free(pt);
}

void remove_page_table(void){
	struct thread* t = thread_current();
	hash_destroy(&t->page_table, pt_destroy);
}

int grow_stack(void* addr){
	//max stack size
	if((size_t)(PHYS_BASE - pg_round_down(addr)) > MAX_STACK_SIZE){
		//printf("max\n");
		return 0;
	}
	struct page_table_entry* pt = malloc(sizeof(struct page_table_entry));
	if(!pt){
		return 0;
	}
	uint8_t* page = get_frame(PAL_USER);
	if(!page){
		free(pt);
		return 0;
	}
	pt->addr = pg_round_down(addr);
	//printf("grow addr %d\n", pt->addr);
	//printf("grow base\n");
	pt->loaded = 1;
	pt->write = 1;
	pt->type = 1;
	pt->pinned = 1;
	pt->pagedir = thread_current()->pagedir;
	struct frame_table_entry* ft = ft_lookup(page);
	//if (ft != NULL){
		ft->pt = pt;
	//}
	//bool success = install_page(pt->addr, page, pt->write);
	bool success = pagedir_set_page(pt->pagedir, pt->addr, page, (bool)pt->write);
	if(!success){
		free_frame(page);
		free(pt);
		return 0;
	}

	if(intr_context()){
		pt->pinned = 0;
	}
	//printf("grow pinned %d %d\n", pt->pinned, pt->loaded);
	success = hash_insert(&thread_current()->page_table, &pt->hash_elem);
	if(success != NULL){
		//printf("hash grow fail\n");
		free_frame(page);	
		free(pt);
		return 0;
	}
	return 1;
}



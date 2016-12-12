#include "vm/frame_table.h"
#include "vm/page_table.h"
#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"



unsigned ft_get_hash(const struct hash_elem *p_, void *aux UNUSED){
	const struct frame_table_entry *p = hash_entry(p_, struct frame_table_entry, hash_elem);
	return hash_int((unsigned)p->page);
}

bool ft_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
	const struct frame_table_entry *a = hash_entry(a_, struct frame_table_entry, hash_elem);
	const struct frame_table_entry *b = hash_entry(b_, struct frame_table_entry, hash_elem);
	return a->page < b->page;
}

void frame_table_init(void){
	lock_init(&ft_lock);
	hash_init(&ft_hash, ft_get_hash, ft_less, NULL);
	list_init(&ft_list);
}


void* get_frame(enum palloc_flags flags){
	void* page = palloc_get_page(flags);
	//printf("get frame\n");
	if (page == NULL){
		while(page == NULL){
			//printf("is evicting\n");
			evict();
			//page = evict(flags);
			page = palloc_get_page(flags);
			lock_release(&ft_lock);
			//printf("unlock %d %x\n", thread_current()->tid, page);
		}
	}
	//assumes will succeed eventually
	struct frame_table_entry *ft = malloc(sizeof(struct frame_table_entry));
	ft->page = page;
	ft->thread = thread_current();
	ft->pagedir = thread_current()->pagedir;
	//ft->pte = 
	//printf("before list\n");
	lock_acquire(&ft_lock);
	hash_insert(&ft_hash, &ft->hash_elem);
	list_push_back(&ft_list, &ft->list_elem);
	lock_release(&ft_lock);
	//printf("after list\n");
	return page;
}

void free_frame(void *page){
	struct frame_table_entry* ft = ft_lookup(page);
	if (ft == NULL){
		//handle this
		return NULL;
	}
	//printf("free fram\n");
	lock_acquire(&ft_lock);
	hash_delete(&ft_hash, &ft->hash_elem);
	list_remove(&ft->list_elem);
	free(ft);
	lock_release(&ft_lock);
	palloc_free_page(page);
}	

struct frame_table_entry* ft_lookup(void* page){
	struct frame_table_entry ft;
	struct hash_elem *e;
	ft.page = page;
	e = hash_find(&ft_hash, &ft.hash_elem);
	return e != NULL ? hash_entry(e, struct frame_table_entry, hash_elem) : NULL;
}
//void* evict(enum palloc_flags flags){
void evict(void){
	//printf("evict\n");
	//printf("lock %d\n", thread_current()->tid);
	lock_acquire(&ft_lock);
	struct list_elem *e = list_begin(&ft_list);
	struct frame_table_entry *ft;

	struct frame_table_entry *v = NULL;
	while(v == NULL){
		//printf("iteration\n");
		ft = list_entry(e, struct frame_table_entry, list_elem);
		if(ft->pt->pinned == 0){
			//printf("what\n");
		}
		//printf("a %d %x %x %x\n", thread_current()->tid, ft->pagedir, ft->page, ft->pt->addr);
		if(ft->pt->pinned == 0){
			//printf("b %d  %x %x %x\n", thread_current()->tid, ft->pagedir, ft->page, ft->pt->addr);
			if(pagedir_is_accessed(ft->pagedir, ft->pt->addr)){
				//printf("is accessed\n");
				pagedir_set_accessed(ft->pagedir, ft->pt->addr, false);
			}
			else{
				//v
				//printf("found\n");
				v = ft;
				if(pagedir_is_dirty(ft->pagedir, ft->pt->addr) || ft->pt->type == 1){
					//printf("evict type=1\n");					
					ft->pt->type = 1;
					ft->pt->swap_ind = swap_out(ft->page);
					//ft->pt->swap_ind = swap_out(ft->page);
					//if (ft->pt->swap_ind == 0){
						//printf("stack swap out %d %d\n", ft->page, ft->pt->addr);
					//}
				}
				ft->pt->loaded = 0;
				list_remove(&ft->list_elem);
				hash_delete(&ft_hash, &ft->hash_elem);
				pagedir_clear_page(ft->pagedir, ft->pt->addr);
				palloc_free_page(ft->page);
				free(ft);
				return;
				//break;
			}
		}
		e = list_next(e);
		if(e == list_end(&ft_list)){
			e = list_begin(&ft_list);
		}
		
	}
	/*
	v->pt->loaded = 0;
	list_remove(&v->list_elem);
	hash_delete(&ft_hash, &v->hash_elem);
	pagedir_clear_page(v->pagedir, v->pt->addr);
	palloc_free_page(v->page);
	free(v);
	lock_release(&ft_lock);
	*/
}

#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "vm/swap.h"


void swap_init(void){
	//printf("swap init\n");
	swap_block = block_get_role(BLOCK_SWAP);
	if(!swap_block){
		printf("swap block failed\n");
		return;
	}
	//printf("swap init2\n");
	swap_bitmap = bitmap_create(block_size(swap_block) / BLOCKS_PER_PAGE);
	if(!swap_bitmap){
		return;
	}
	//printf("swap init3\n");
	bitmap_set_all(swap_bitmap, 0);
	lock_init(&swap_lock);
}

size_t swap_out(void* page){
	//printf("swap out %d\n", page);
	lock_acquire(&swap_lock);
	//printf("after lock\n");
	//find consecutive 0s (last param), flip
	size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 1, 0);
	//printf("after scanflip\n");
	if(index == BITMAP_ERROR){
		PANIC("No bits\n");
	}
	//if (index == 0){
		//printf("setup stack swap out %d\n", page);
	//}
	size_t i;
	//memory to swap
	for(i = 0; i < BLOCKS_PER_PAGE; i += 1){
		block_write(swap_block, (index * BLOCKS_PER_PAGE) + i, 
		(uint8_t *) page + (i * BLOCK_SECTOR_SIZE));
	}
	lock_release(&swap_lock);
	//printf("swap before released %d\n", thread_current()->tid);
	return index;
}

void swap_in(size_t index, void* page){
	//printf("swap in %d %d\n",index, page);
	lock_acquire(&swap_lock);
	size_t i;
	//printf("after lock in\n");
	//if (bitmap_test(swap_bitmap, index) == 0){
		//PANIC("swap in free\n");
	//}
	//swap slot to memory
	bitmap_flip(swap_bitmap, index);
	//printf("after in flip\n");
	for(i = 0; i < BLOCKS_PER_PAGE; i += 1){
		block_read(swap_block, (index * BLOCKS_PER_PAGE) + i, 
(uint8_t *) page + (i * BLOCK_SECTOR_SIZE));
	}
	
	lock_release(&swap_lock);
	//printf("in done %d\n", thread_current()->tid);
}

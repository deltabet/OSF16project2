
#include <stdbool.h>
#include <stddef.h>

#define BLOCKS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);
size_t swap_out(void* page);
void swap_in(size_t index, void* page);

struct block* swap_block;
struct bitmap *swap_bitmap;
struct lock swap_lock;


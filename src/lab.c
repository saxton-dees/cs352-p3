#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);          \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes)
{
    if (bytes == 0) return 0;

    size_t k = 0;
    size_t value = 1;

    // Find the smallest power of 2 greater than or equal to bytes
    while (value < bytes) {
        value <<= 1; // Multiply value by 2
        k++;
    }

    return k;
}

/**
 * @brief Calculate the buddy of a given memory block.
 * 
 * @param pool The memory pool to work on (needed for the base addresses)
 * @param buddy The memory block that we want to find the buddy for
 * @return A pointer to the buddy
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy)
{
    // Calculate the size of the block (2^kval)
    size_t block_size = (size_t)1 << buddy->kval;

    // Calculate the offset of the buddy relative to the base address
    size_t offset = (void *)buddy - pool->base;

    // Flip the bit corresponding to the block size to find the buddy's offset
    size_t buddy_offset = offset ^ block_size;

    // Return the pointer to the buddy by adding the buddy offset to the base address
    return (struct avail *)(pool->base + buddy_offset);
}

/**
 * @brief Allocate memory using the buddy system.
 *
 * @param pool The memory pool to allocate from
 * @param size The size of memory to allocate
 * @return Pointer to the allocated memory, or NULL if allocation fails
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    //get the kval for the requested size with enough room for the tag and kval fields
    //R1 Find a block
    //There was not enough memory to satisfy the request thus we need to set error and return NULL
    //R2 Remove from list;
    //R3 Split required?
    //R4 Split the block

    if (pool == NULL || size == 0) {
        errno = EINVAL;
        return NULL;
    }

    // Step 1: Calculate the required kval
    size_t required_kval = btok(size + sizeof(struct avail));
    if (required_kval < SMALLEST_K) {
        required_kval = SMALLEST_K;
    }

    // Step 2: Find a suitable block
    size_t current_kval = required_kval;
    while (current_kval <= pool->kval_m && pool->avail[current_kval].next == &pool->avail[current_kval]) {
        current_kval++;
    }

    // If no suitable block is found, return NULL
    if (current_kval > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // Step 3: Remove the block from the free list
    struct avail *block = pool->avail[current_kval].next;
    block->prev->next = block->next;
    block->next->prev = block->prev;

    // Step 4: Split the block (if necessary)
    while (current_kval > required_kval) {
        current_kval--;
        size_t block_size = (size_t)1 << current_kval;

        // Calculate the buddy of the block
        struct avail *buddy = (struct avail *)((void *)block + block_size);

        // Initialize the buddy block
        buddy->kval = current_kval;
        buddy->tag = BLOCK_AVAIL;

        // Add the buddy to the free list
        buddy->next = pool->avail[current_kval].next;
        buddy->prev = &pool->avail[current_kval];
        pool->avail[current_kval].next->prev = buddy;
        pool->avail[current_kval].next = buddy;
    }

    // Step 5: Mark the block as reserved
    block->tag = BLOCK_RESERVED;
    block->kval = required_kval;

    // Return a pointer to the memory region after the metadata
    return (void *)(block + 1);
}

/**
 * @brief Free a previously allocated memory block.
 *
 * @param pool The memory pool to free from
 * @param ptr Pointer to the memory block to free
 */
void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (pool == NULL || ptr == NULL) {
        return; // Do nothing if pool or ptr is NULL
    }

    // Step 1: Locate the block metadata
    struct avail *block = (struct avail *)ptr - 1;

    // Step 2: Mark the block as available
    block->tag = BLOCK_AVAIL;

    // Step 3: Attempt to merge with buddy
    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        // Check if the buddy is free and has the same kval
        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval) {
            break; // Stop merging if buddy is not free or not the same size
        }

        // Remove the buddy from the free list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Merge the block and buddy into a larger block
        if (buddy < block) {
            block = buddy; // The merged block starts at the lower address
        }
        block->kval++;
    }

    // Step 4: Add the resulting block to the free list
    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next->prev = block;
    pool->avail[block->kval].next = block;
}


/**
 * @brief Initialize the buddy memory pool.
 *
 * @param pool The memory pool to initialize
 * @param size The size of the memory pool in bytes
 */
void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

/**
 * @brief Destroy the buddy memory pool and free the resources.
 *
 * @param pool The memory pool to destroy
 */
void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}

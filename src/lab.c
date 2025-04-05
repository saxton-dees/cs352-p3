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

// Macro to handle errors and terminate the program
#define handle_error_and_die(msg) \
    do {                          \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

// Macro to suppress unused variable warnings
#define UNUSED(x) (void)(x)

/**
 * @brief Convert bytes to the smallest power of 2 (K value) that can fit the bytes.
 *
 * @param bytes The number of bytes.
 * @return size_t The K value.
 */
size_t btok(size_t bytes) {
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
 * @brief Calculate the buddy address for a given memory block.
 *
 * @param pool The memory pool (needed for base addresses).
 * @param buddy The memory block to find the buddy for.
 * @return A pointer to the buddy block.
 */
struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    size_t buddy_offset = (size_t)buddy - (size_t)pool->base;
    size_t buddy_size = 1 << buddy->kval;
    size_t buddy_index = buddy_offset / buddy_size;

    // XOR with 1 to find the buddy index
    size_t buddy_index_pair = buddy_index ^ 1;

    // Calculate the address of the buddy block
    return (struct avail *)((char *)pool->base + (buddy_index_pair * buddy_size));
}

/**
 * @brief Allocate a block of memory from the buddy system.
 *
 * @param pool The memory pool.
 * @param size The size of the requested memory block in bytes.
 * @return A pointer to the allocated memory block.
 */
void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (pool == NULL || size == 0) return NULL;

    // Calculate the required K value for the requested size (including metadata)
    size_t required_kval = btok(size + sizeof(struct avail));
    if (required_kval < SMALLEST_K) required_kval = SMALLEST_K;

    // Find the smallest available block that can satisfy the request
    size_t current_kval = required_kval;
    while (current_kval <= pool->kval_m && pool->avail[current_kval].next == &pool->avail[current_kval]) {
        current_kval++;
    }

    // If no block is large enough, return NULL
    if (current_kval > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // Remove the block from the free list
    struct avail *block = pool->avail[current_kval].next;
    block->prev->next = block->next;
    block->next->prev = block->prev;

    // Split the block if necessary
    while (current_kval > required_kval) {
        current_kval--;
        size_t split_size = 1 << current_kval;

        // Create a new buddy block
        struct avail *buddy = (struct avail *)((char *)block + split_size);
        buddy->tag = BLOCK_AVAIL;
        buddy->kval = current_kval;

        // Add the buddy block to the free list
        buddy->next = pool->avail[current_kval].next;
        buddy->prev = &pool->avail[current_kval];
        pool->avail[current_kval].next->prev = buddy;
        pool->avail[current_kval].next = buddy;
    }

    // Mark the block as reserved and return it
    block->tag = BLOCK_RESERVED;
    block->kval = required_kval;
    return (void *)((char *)block + sizeof(struct avail));
}

/**
 * @brief Free a block of memory back to the buddy system.
 *
 * @param pool The memory pool.
 * @param ptr Pointer to the memory block to free.
 */
void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (pool == NULL || ptr == NULL) return;

    // Get the metadata block
    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));

    // Mark the block as available
    block->tag = BLOCK_AVAIL;

    // Attempt to coalesce with the buddy block
    struct avail *buddy = buddy_calc(pool, block);
    if (buddy->tag == BLOCK_AVAIL && buddy->kval == block->kval) {
        // Remove buddy from the free list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Merge the blocks
        if (block < buddy) {
            block->kval++;
        } else {
            buddy->kval++;
            block = buddy;
        }
    }

    // Add the (possibly merged) block back to the free list
    block->next = pool->avail[block->kval].next;
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next->prev = block;
    pool->avail[block->kval].next = block;
}

/**
 * @brief Reallocate a block of memory.
 *
 * @param pool The memory pool.
 * @param ptr Pointer to the memory block.
 * @param size The new size of the memory block.
 * @return Pointer to the new memory block.
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {
    if (pool == NULL) return NULL;
    if (ptr == NULL) return buddy_malloc(pool, size);
    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    // Get the metadata block
    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));

    // Check if the current block is large enough
    size_t required_kval = btok(size + sizeof(struct avail));
    if (required_kval <= block->kval) return ptr;

    // Allocate a new block and copy the data
    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr == NULL) return NULL;

    memcpy(new_ptr, ptr, (1 << block->kval) - sizeof(struct avail));
    buddy_free(pool, ptr);
    return new_ptr;
}

/**
 * @brief Initialize the buddy memory pool.
 *
 * @param pool The buddy pool to initialize.
 * @param size The size of the memory pool in bytes.
 */
void buddy_init(struct buddy_pool *pool, size_t size) {
    size_t kval = (size == 0) ? DEFAULT_K : btok(size);
    if (kval < MIN_K) kval = MIN_K;
    if (kval > MAX_K) kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);

    // Memory map a block of raw memory
    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED) handle_error_and_die("buddy_init mmap failed");

    // Initialize the free lists
    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    // Add the initial block to the largest free list
    struct avail *initial_block = (struct avail *)pool->base;
    initial_block->tag = BLOCK_AVAIL;
    initial_block->kval = kval;
    initial_block->next = initial_block->prev = &pool->avail[kval];
    pool->avail[kval].next = pool->avail[kval].prev = initial_block;
}

/**
 * @brief Destroy the buddy memory pool.
 *
 * @param pool The memory pool to destroy.
 */
void buddy_destroy(struct buddy_pool *pool) {
    if (munmap(pool->base, pool->numbytes) == -1) handle_error_and_die("buddy_destroy munmap failed");
    memset(pool, 0, sizeof(struct buddy_pool));
}

/**
 * @brief Print the binary representation of a number (for debugging).
 *
 * @param b The number to print.
 */
static void printb(unsigned long int b) {
    size_t bits = sizeof(b) * 8;
    unsigned long int curr = UINT64_C(1) << (bits - 1);
    for (size_t i = 0; i < bits; i++) {
        printf("%c", (b & curr) ? '1' : '0');
        curr >>= 1;
    }
}

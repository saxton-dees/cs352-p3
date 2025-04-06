#include <assert.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif
#include "harness/unity.h"
#include "../src/lab.h"


void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}

/**
 * Tests the btok function to ensure it calculates the correct K value.
 */
void test_btok(void) {
  fprintf(stderr, "->Testing btok function\n");

  // Test case: 0 bytes should return 0
  size_t result = btok(0);
  assert(result == 0);

  // Test case: 1 byte should return 0 (2^0 = 1)
  result = btok(1);
  assert(result == 0);

  // Test case: 2 bytes should return 1 (2^1 = 2)
  result = btok(2);
  assert(result == 1);

  // Test case: 3 bytes should return 2 (next power of 2 is 4)
  result = btok(3);
  assert(result == 2);

  // Test case: 8 bytes should return 3 (2^3 = 8)
  result = btok(8);
  assert(result == 3);

  // Test case: 15 bytes should return 4 (next power of 2 is 16)
  result = btok(15);
  assert(result == 4);

  // Test case: 16 bytes should return 4 (2^4 = 16)
  result = btok(16);
  assert(result == 4);

  // Test case: 1023 bytes should return 10 (next power of 2 is 1024)
  result = btok(1023);
  assert(result == 10);

  // Test case: 1024 bytes should return 10 (2^10 = 1024)
  result = btok(1024);
  assert(result == 10);

  // Test case: Large value (e.g., 1 << 20 = 1 MB)
  result = btok(1 << 20);
  assert(result == 20);

  fprintf(stderr, "btok tests passed.\n");
}


/**
 * Tests the buddy_calc function to ensure it returns the correct buddy addresss.
 */
void test_buddy_calc() {
  struct buddy_pool pool;

  // Initialize the memory pool with a size of 2^MIN_K bytes
  buddy_init(&pool, 1 << MIN_K);

  // Get the base address of the memory pool
  void *base = pool.base;

  // Create a block at the base address with kval = 6 (block size = 2^6 = 64 bytes)
  struct avail *block = (struct avail *)base;
  block->kval = 6;

  // Calculate the buddy of the block
  struct avail *buddy = buddy_calc(&pool, block);

  // The buddy of the block at base should be at base + 64 bytes
  assert((void *)buddy == base + (1 << block->kval));
  printf("Test 1 passed: Buddy of block at base is correct.\n");

  // Create another block at base + 128 bytes with kval = 7 (block size = 2^7 = 128 bytes)
  struct avail *block2 = (struct avail *)(base + 128);
  block2->kval = 7;

  // Calculate the buddy of the block
  struct avail *buddy2 = buddy_calc(&pool, block2);

  // The buddy of the block at base + 128 should be at base (since XOR flips the bit)
  assert((void *)buddy2 == base);
  printf("Test 2 passed: Buddy of block at base + 128 is correct.\n");

  // Clean up the memory pool
  buddy_destroy(&pool);
}

/**
 * Check the pool to ensure it is full.
 */
void check_buddy_pool_full(struct buddy_pool *pool)
{
  //A full pool should have all values 0-(kval-1) as empty
  for (size_t i = 0; i < pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }

  //The avail array at kval should have the base block
  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);

  //Check to make sure the base address points to the starting pool
  //If this fails either buddy_init is wrong or we have corrupted the
  //buddy_pool struct.
  assert(pool->avail[pool->kval_m].next == pool->base);
}

/**
 * Check the pool to ensure it is empty.
 */
void check_buddy_pool_empty(struct buddy_pool *pool)
{
  //An empty pool should have all values 0-(kval) as empty
  for (size_t i = 0; i <= pool->kval_m; i++)
    {
      assert(pool->avail[i].next == &pool->avail[i]);
      assert(pool->avail[i].prev == &pool->avail[i]);
      assert(pool->avail[i].tag == BLOCK_UNUSED);
      assert(pool->avail[i].kval == i);
    }
}

/**
 * Test allocating 1 byte to make sure we split the blocks all the way down
 * to MIN_K size. Then free the block and ensure we end up with a full
 * memory pool again
 */
void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  //Make sure correct kval was allocated
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  // buddy_destroy(&pool);
}

/**
 * Tests the allocation of one massive block that should consume the entire memory
 * pool and makes sure that after the pool is empty we correctly fail subsequent calls.
 */
void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  //Ask for an exact K value to be allocated. This test makes assumptions on
  //the internal details of buddy_init.
  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  //Move the pointer back and make sure we got what we expected
  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  //Verify that a call on an empty tool fails as expected and errno is set to ENOMEM.
  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno = ENOMEM);

  //Free the memory and then check to make sure everything is OK
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

/**
 * Tests to make sure that the struct buddy_pool is correct and all fields
 * have been properly set kval_m, avail[kval_m], and base pointer after a
 * call to init
 */
void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  //Loop through all kval MIN_k-DEFAULT_K and make sure we get the correct amount allocated.
  //We will check all the pointer offsets to ensure the pool is all configured correctly
  for (size_t i = MIN_K; i <= DEFAULT_K; i++)
    {
      size_t size = UINT64_C(1) << i;
      struct buddy_pool pool;
      buddy_init(&pool, size);
      check_buddy_pool_full(&pool);
      buddy_destroy(&pool);
    }
}


int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_btok);
  RUN_TEST(test_buddy_calc);
  RUN_TEST(test_buddy_init);
  // RUN_TEST(test_buddy_malloc_one_byte);
  // RUN_TEST(test_buddy_malloc_one_large);
return UNITY_END();
}

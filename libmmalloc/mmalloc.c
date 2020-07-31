#include <sys/mman.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "mmalloc.h"

#define ALIGNMENT 16
#define MAX_HEAP (100 * (1 << 20))

static uint8_t *heap;
static uint8_t *mem_brk;
static uint8_t *mem_max_addr;

static void *mem_sbrk(long incr) {
  uint8_t *old_brk = mem_brk;

  if ((incr < 0) || ((mem_brk + incr) > mem_max_addr)) {
    errno = ENOMEM;
    return (void *)-1;
  }

  mem_brk += incr;
  return (void *)old_brk;
}

static void *mem_heap_lo() {
  return (void *)heap;
}

static void *mem_heap_hi() {
  return (void *)(mem_brk - 1);
}

typedef uint32_t header_t;
typedef header_t footer_t;
typedef union payload payload_t;
typedef struct block block_t;
typedef struct node node_t;

struct node {
  node_t *left;
  node_t *right;
};

union payload {
  struct {
    node_t node;
  } splay;
  uint8_t payload[0];
};

struct block {
  header_t header;
  payload_t payload;
};

static inline int cmplt(block_t *lhs, block_t *rhs);
static inline int cmpeq(block_t *lhs, block_t *rhs);
static inline int cmpgt(block_t *lhs, block_t *rhs);
static inline node_t *block_node(block_t *block);
static inline block_t *node_to_block(node_t *node);
static inline uint32_t header_size(header_t *header);
static inline uint32_t footer_size(footer_t *footer);
static inline void header_set_size(header_t *header, uint32_t size);
static inline int header_is_used(header_t *header);
static inline int header_is_free(header_t *header);
static inline int footer_is_used(footer_t *footer);
static inline int footer_is_free(footer_t *footer);
static inline void header_set_used(header_t *header);
static inline void header_set_free(header_t *header);
static inline int header_prev_is_used(header_t *header);
static inline int footer_prev_is_used(footer_t *footer);
static inline int header_prev_is_free(header_t *header);
static inline int footer_prev_is_free(footer_t *footer);
static inline void header_prev_set_used(header_t *header);
static inline void header_prev_set_free(header_t *header);
static inline header_t *block_header(block_t *block);
static inline footer_t *block_footer(block_t *block);
static inline void block_set_size(block_t *block, uint32_t size);
static inline void block_footer_sync(block_t *block);
static inline void *block_payload(block_t *block);
static inline block_t *block_phys_next(block_t *block);
static inline block_t *block_phys_prev(block_t *block);
static inline uint32_t block_size(block_t *block);
static inline int block_is_used(block_t *block);
static inline int block_is_free(block_t *block);
static inline void block_set_used(block_t *block);
static inline void block_set_free(block_t *block);
static inline int block_prev_is_used(block_t *block);
static inline int block_prev_is_free(block_t *block);
static inline void block_prev_set_used(block_t *block);
static inline void block_prev_set_free(block_t *block);
static inline block_t *payload_to_block(void *ptr);
static inline size_t round_up(size_t size);

/*
 * http://www.link.cs.cmu.edu/link/ftp-site/splaying/top-down-splay.c
 */

static node_t *splay(block_t *block, node_t *t) {
  node_t N, *l, *r, *y;
  if (NULL == t)
    return t;
  N.left = N.right = NULL;
  l = r = &N;

  for (;;) {
    if (cmplt(block, node_to_block(t))) {
      if (NULL == t->left)
        break;
      if (cmplt(block, node_to_block(t->left))) {
        y = t->left;
        t->left = y->right;
        y->right = t;
        t = y;
        if (NULL == t->left)
          break;
      }
      r->left = t;
      r = t;
      t = t->left;
    } else if (cmpgt(block, node_to_block(t))) {
      if (NULL == t->right)
        break;
      if (cmpgt(block, node_to_block(t->right))) {
        y = t->right;
        t->right = y->left;
        y->left = t;
        t = y;
        if (NULL == t->right)
          break;
      }
      l->right = t;
      l = t;
      t = t->right;
    } else {
      break;
    }
  }
  l->right = t->left;
  r->left = t->right;
  t->left = N.right;
  t->right = N.left;
  return t;
}

static node_t *insert(node_t *new, node_t *t) {
  if (NULL == t) {
    new->left = new->right = NULL;
    return new;
  }
  t = splay(node_to_block(new), t);
  if (cmplt(node_to_block(new), node_to_block(t))) {
    new->left = t->left;
    new->right = t;
    t->left = NULL;
    return new;
  } else if (cmpgt(node_to_block(new), node_to_block(t))) {
    new->right = t->right;
    new->left = t;
    t->right = NULL;
    return new;
  } else {
    return t;
  }
}

static node_t *delete(block_t *block, node_t *t) {
  node_t *x;
  if (NULL == t)
    return NULL;
  t = splay(block, t);
  if (cmpeq(block, node_to_block(t))) {
    if (NULL == t->left) {
      x = t->right;
    } else {
      x = splay(block, t->left);
      x->right = t->right;
    }
    return x;
  }
  return t;
}

static node_t *find_block(uint32_t size, node_t *t) {
  if (NULL == t)
    return NULL;
  if (size == block_size(node_to_block(t)))
    return t;
  if (size < block_size(node_to_block(t))) {
    node_t *ret = find_block(size, t->left);
    return ret ? ret : t;
  }
  return find_block(size, t->right);
}

static node_t *find(uint32_t size, node_t **t) {
  node_t *ret = find_block(size, *t);
  if (ret)
    *t = splay(node_to_block(ret), *t);
  return ret;
}

static node_t *mm_root;
int mminit(void) {
  heap = mmap((void *)0x800000000, MAX_HEAP, PROT_WRITE, MAP_PRIVATE | MAP_ANON,
              -1, 0);
  mem_max_addr = heap + MAX_HEAP;
  mem_brk = heap;

  if ((long)mem_sbrk(ALIGNMENT - offsetof(block_t, payload)) < 0)
    return -1;

  mm_root = NULL;
  return 0;
}

void mmdeinit(void) {
  munmap(heap, MAX_HEAP);
}

static block_t *split(block_t *block, int32_t size) {
  node_t *node;
  block_t *nblock;
  uint32_t osize = block_size(block);
  
  block_set_size(block, size);
  nblock = block_phys_next(block);
  block_set_size(nblock, osize - size);
  block_set_free(nblock);

  node = block_node(nblock);
  node->left = NULL;
  node->right = NULL;

  return nblock;
}

static inline block_t *block_alloc(uint32_t size) {
  block_t *block = mem_sbrk(size);
  if ((long)block < 0)
    return NULL;

  block_set_size(block, size);
  return block;
}

static inline block_t *block_find(uint32_t size, node_t **root) {
  node_t *ret = find(size, root);
  if (NULL == ret)
    return NULL;
  return node_to_block(ret);
}

void *mmalloc(size_t size) {
  if (0 == size)
    return NULL;

  size = round_up(sizeof(block_t) + size);
  block_t *block = block_find(size, &mm_root);
  block_t *nblock;
  block_t *prev;

  if (NULL == block) {
    block = block_alloc(size);
    if (NULL == block) {
      errno =  ENOMEM;
      return NULL;
    }

    prev = block_phys_prev(block);

    if (NULL != prev) {
      if (block_is_free(prev))
        block_prev_set_free(block);
    }

    block_set_used(block);

    return block_payload(block);
  }

  mm_root = delete(block, mm_root);

  if (block_size(block) >= size + sizeof(block_t) + ALIGNMENT) {
    nblock = split(block, size);
    mm_root = insert(block_node(nblock), mm_root);
  }

  block_set_used(block);
  return block_payload(block);
}

static void merge(block_t *block, block_t *next_block, node_t **root) {
  uint32_t bsize = block_size(block);
  uint32_t nbsize = block_size(next_block);
  uint32_t size = bsize + nbsize;

  *root = delete(block, *root);
  *root = delete(next_block, *root);

  block_set_size(block, size);
  *root = insert(block_node(block), *root);
}

void mmfree(void *ptr) {
  block_t *p;
  block_t *block;

  if (!ptr)
    return;

  block = payload_to_block(ptr);
  block_set_free(block);
  mm_root = insert(block_node(block), mm_root);

  while ((p = block_phys_prev(block)) != NULL) {
    if (block_is_free(p) && p != block) {
      merge(p, block, &mm_root);
      block = p;
    } else {
      break;
    }
  }

  while ((p = block_phys_next(block)) != NULL) {
    if (block_is_free(p) && p != block) {
      merge(block, p, &mm_root);
    } else {
      break;
    }
  }
}

void *mmrealloc(void *old_ptr, size_t size) {
  block_t *block;
  block_t *nblock;
  block_t *next;
  block_t *prev;
  size_t old_size;
  size_t tmp_size;
  uint32_t nsize;
  uint32_t osize;
  uint32_t psize;
  void *nptr;

  if (size == 0) {
    mmfree(old_ptr);
    return NULL;
  }

  if (!old_ptr) {
    return mmalloc(size);
  }

  tmp_size = size;
  size = round_up(sizeof(block_t) + size);

  block = payload_to_block(old_ptr);
  old_size = block_size(block);

  if (size <= block_size(block)) {
    if (block_size(block) >= size + sizeof(block_t) + ALIGNMENT) {
      block_t *nblock = split(block, size);
      mm_root = insert(block_node(nblock), mm_root);
    }

    return old_ptr;
  }

  for (;;) {
    next = block_phys_next(block);
    if (NULL != next && block_is_free(next)) {
      osize = block_size(block);
      nsize = block_size(next);
      mm_root = delete (next, mm_root);
      block_set_size(block, osize + nsize);
    } else {
      break;
    }
    if (block_size(block) >= size) {
      return old_ptr;
    }
  }

  for (;;) {
    prev = block_phys_prev(block);
    if (NULL != prev && block_is_free(prev)) {
      osize = block_size(block);
      psize = block_size(prev);
      if (osize + psize >= size) {
        mm_root = delete(prev, mm_root);
        block_set_size(prev, osize + psize);

        memmove(block_payload(prev), old_ptr, old_size);
        block_set_used(prev);

        if (block_size(prev) >= size + sizeof(block_t) + ALIGNMENT) {
          nblock = split(prev, size);
          mm_root = insert(block_node(nblock), mm_root);
        }

        return block_payload(prev);
      } else {
        break;
      }
    } else {
      break;
    }
  }

  if (!(nptr = mmalloc(tmp_size)))
    return NULL;

  if (size < old_size)
    old_size = size;

  memcpy(nptr, old_ptr, old_size);
  mmfree(old_ptr);
  return nptr;
}

void *mmcalloc(size_t nmemb, size_t size) {
  size_t bytes = nmemb * size;
  void *nptr = mmalloc(bytes);
  if (nptr)
    memset(nptr, 0, bytes);
  return nptr;
}

static inline size_t round_up(size_t size) {
  return (size + ALIGNMENT - 1) & -ALIGNMENT;
}

static inline uint32_t header_size(header_t *header) {
  return (*header >> 4) << 4;
}

static inline uint32_t footer_size(footer_t *footer) {
  return (*footer >> 4) << 4;
}

static inline void header_set_size(header_t *header, uint32_t size) {
  *header &= 0x3;
  *header |= size;
}

static inline int header_is_used(header_t *header) { 
  return *header & 0x1; 
}

static inline int header_is_free(header_t *header) {
  return !header_is_used(header);
}

static inline int footer_is_used(footer_t *footer) { 
  return *footer & 0x1; 
}

static inline int footer_is_free(footer_t *footer) {
  return !footer_is_used(footer);
}

static inline void header_set_used(header_t *header) { 
  *header |= 0x1; 
}

static inline void header_set_free(header_t *header) { 
  *header &= 0xfffffffe; 
}

static inline int header_prev_is_used(header_t *header) {
  return *header & 0x2;
}

static inline int footer_prev_is_used(footer_t *footer) {
  return *footer & 0x2;
}

static inline int header_prev_is_free(header_t *header) {
  return !header_prev_is_used(header);
}

static inline int footer_prev_is_free(footer_t *footer) {
  return !footer_prev_is_used(footer);
}

static inline void header_prev_set_used(header_t *header) { 
  *header |= 0x2; 
}

static inline void header_prev_set_free(header_t *header) {
  *header &= 0xfffffffd;
}

static inline header_t *block_header(block_t *block) { 
  return &block->header;
}

static inline footer_t *block_footer(block_t *block) {
  int32_t size = header_size(block_header(block));
  void *ptr = block;
  ptr += size;
  ptr -= sizeof(footer_t);
  return (footer_t *)ptr;
}

static inline void block_set_size(block_t *block, uint32_t size) {
  header_set_size(block_header(block), size);
  block_footer_sync(block);
}

static inline void block_footer_sync(block_t *block) {
  *block_footer(block) = *block_header(block);
}

static inline void *block_payload(block_t *block) {
  return block->payload.payload;
}

static inline block_t *block_phys_next(block_t *block) {
  int32_t size = block_size(block);
  void *ptr = block;
  ptr += size;
  if (ptr > mem_heap_hi())
    return NULL;
  return (block_t *)ptr;
}

static inline block_t *block_phys_prev(block_t *block) {
  void *ptr = block;
  ptr -= sizeof(footer_t);
  if (ptr < mem_heap_lo())
    return NULL;

  footer_t *footer = (footer_t *)ptr;
  ptr = block;
  ptr -= footer_size(footer);

  if (ptr < mem_heap_lo() || ptr == block)
    return NULL;

  return (block_t *)ptr;
}

static inline uint32_t block_size(block_t *block) {
  return header_size(block_header(block));
}

static inline int block_is_used(block_t *block) {
  return header_is_used(block_header(block));
}

static inline int block_is_free(block_t *block) {
  return !block_is_used(block);
}

static inline void block_set_used(block_t *block) {
  header_set_used(block_header(block));
  block_footer_sync(block);

  block_t *next = block_phys_next(block);
  if (NULL != next) {
    block_prev_set_used(next);
  }
}

static inline void block_set_free(block_t *block) {
  header_set_free(block_header(block));
  block_footer_sync(block);

  block_t *next = block_phys_next(block);
  if (NULL != next) {
    block_prev_set_free(next);
  }
}

static inline int block_prev_is_used(block_t *block) {
  return header_prev_is_used(block_header(block));
}

static inline int block_prev_is_free(block_t *block) {
  return !block_prev_is_used(block);
}

static inline void block_prev_set_used(block_t *block) {
  header_prev_set_used(block_header(block));
  block_footer_sync(block);
}

static inline void block_prev_set_free(block_t *block) {
  header_prev_set_free(block_header(block));
  block_footer_sync(block);
}

static inline block_t *payload_to_block(void *ptr) {
  ptr -= offsetof(block_t, payload);
  return (block_t *)ptr;
}

static inline node_t *block_node(block_t *block) {
  return &block->payload.splay.node;
}

static inline int cmplt(block_t *lhs, block_t *rhs) {
  int32_t slhs = block_size(lhs);
  int32_t srhs = block_size(rhs);
  if (slhs == srhs)
    return lhs < rhs;
  return slhs < srhs;
}

static inline int cmpeq(block_t *lhs, block_t *rhs) { 
  return lhs == rhs; 
}

static inline int cmpgt(block_t *lhs, block_t *rhs) {
  int32_t slhs = block_size(lhs);
  int32_t srhs = block_size(rhs);
  if (slhs == srhs)
    return lhs > rhs;
  return slhs > srhs;
}

static inline block_t *node_to_block(node_t *node) {
  void *ptr = node;
  ptr -= offsetof(block_t, payload);
  return (block_t *)ptr;
}

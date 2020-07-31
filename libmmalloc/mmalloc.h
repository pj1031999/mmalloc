#ifndef _MMALLOC_H_
#define _MMALLOC_H_

#include <stddef.h>

int mminit(void);
void mmdeinit(void);
void *mmalloc(size_t size);
void *mmcalloc(size_t nmemb, size_t size);
void *mmrealloc(void *ptr, size_t size);
void mmfree(void *ptr);

#endif /* !_MMALLOC_H_ */

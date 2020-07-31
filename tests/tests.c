#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include "minunit.h"
#include "mmalloc.h"

MU_TEST(mmalloc_NULL) {
  void *ptr;
  mu_check((ptr = mmalloc(0)) == NULL);
}

MU_TEST(mmalloc_ENOMEM) {
  void *ptr;
  mu_check((ptr = mmalloc(134217728)) == NULL);
  mu_check(ENOMEM == errno);
}

MU_TEST(mmalloc_4) {
  void *ptr;
  mu_check((ptr = mmalloc(4)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_8) {
  void *ptr;
  mu_check((ptr = mmalloc(8)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_16) {
  void *ptr;
  mu_check((ptr = mmalloc(16)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_32) {
  void *ptr;
  mu_check((ptr = mmalloc(32)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_64) {
  void *ptr;
  mu_check((ptr = mmalloc(64)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_128) {
  void *ptr;
  mu_check((ptr = mmalloc(128)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_1024) {
  void *ptr;
  mu_check((ptr = mmalloc(1024)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_2048) {
  void *ptr;
  mu_check((ptr = mmalloc(2048)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_4096) {
  void *ptr;
  mu_check((ptr = mmalloc(4096)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_8192) {
  void *ptr;
  mu_check((ptr = mmalloc(8192)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_16384) {
  void *ptr;
  mu_check((ptr = mmalloc(16384)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_1048576) {
  void *ptr;
  mu_check((ptr = mmalloc(1048576)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_4194304) {
  void *ptr;
  mu_check((ptr = mmalloc(4194304)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmalloc_33554432) {
  void *ptr;
  mu_check((ptr = mmalloc(33554432)) != NULL);
  mmfree(ptr);
}

MU_TEST(mmcalloc_4) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(4, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 4; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_8) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(8, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 8; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_16) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(16, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 16; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_32) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(32, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 32; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_64) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(64, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 64; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_128) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(128, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 128; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_1024) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(1024, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 1024; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_2048) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(2048, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 2048; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_4096) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(4096, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 4096; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_8192) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(8192, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 8192; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_16384) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(16384, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 16384; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_1048576) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(1048576, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 1048576; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_4194304) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(4194304, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 4194304; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmcalloc_33554432) {
  uint8_t *ptr;
  mu_check((ptr = mmcalloc(33554432, sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 33554432; ++i) {
    mu_check(0 == ptr[i]);
  }
  mmfree(ptr);
}

MU_TEST(mmrealloc_common) {
  uint8_t *ptr;

  mu_check((ptr = mmalloc(32 * sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 32; ++i) {
    ptr[i] = i;
  }

  ptr = mmrealloc(ptr, 64 * sizeof(uint8_t));
  for (size_t i = 0; i < 32; ++i) {
    mu_check(i == ptr[i]);
  }

  ptr = mmrealloc(ptr, 16 * sizeof(uint8_t));
  for (size_t i = 0; i < 16; ++i) {
    mu_check(i == ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST_SUITE(powerof2_tests) {
  mu_check(mminit() == 0);
  MU_RUN_TEST(mmalloc_NULL);
  MU_RUN_TEST(mmalloc_ENOMEM);
  MU_RUN_TEST(mmalloc_4);
  MU_RUN_TEST(mmalloc_8);
  MU_RUN_TEST(mmalloc_16);
  MU_RUN_TEST(mmalloc_32);
  MU_RUN_TEST(mmalloc_64);
  MU_RUN_TEST(mmalloc_128);
  MU_RUN_TEST(mmalloc_1024);
  MU_RUN_TEST(mmalloc_2048);
  MU_RUN_TEST(mmalloc_4096);
  MU_RUN_TEST(mmalloc_8192);
  MU_RUN_TEST(mmalloc_16384);
  MU_RUN_TEST(mmalloc_1048576);
  MU_RUN_TEST(mmalloc_4194304);
  MU_RUN_TEST(mmalloc_33554432);
  MU_RUN_TEST(mmcalloc_4);
  MU_RUN_TEST(mmcalloc_8);
  MU_RUN_TEST(mmcalloc_16);
  MU_RUN_TEST(mmcalloc_32);
  MU_RUN_TEST(mmcalloc_64);
  MU_RUN_TEST(mmcalloc_128);
  MU_RUN_TEST(mmcalloc_1024);
  MU_RUN_TEST(mmcalloc_2048);
  MU_RUN_TEST(mmcalloc_4096);
  MU_RUN_TEST(mmcalloc_8192);
  MU_RUN_TEST(mmcalloc_16384);
  MU_RUN_TEST(mmcalloc_1048576);
  MU_RUN_TEST(mmcalloc_4194304);
  MU_RUN_TEST(mmcalloc_33554432);
  MU_RUN_TEST(mmrealloc_common);
  mmdeinit();
}

MU_TEST(mmalloc_linear) {
  void *ptr;
  for (size_t i = 1; i < 4096; ++i) {
    mu_check((ptr = mmalloc(i)) != NULL);
    mmfree(ptr);
  }
}

MU_TEST(mmcalloc_linear) {
  uint8_t *ptr;
  for (size_t i = 1; i < 4096; ++i) {
    mu_check((ptr = mmcalloc(i, sizeof(uint8_t))) != NULL);
    for (size_t j = 0; j < i; ++j) {
      mu_check(ptr[j] == 0);
    }
    mmfree(ptr);
  }
}

MU_TEST(mmrealloc_linear) {
  uint8_t *ptr;

  mu_check((ptr = mmalloc(42 * sizeof(uint8_t))) != NULL);
  for (size_t i = 0; i < 42; ++i) {
    ptr[i] = i;
  }

  for (size_t i = 42; i < 4096; ++i) {
    ptr = mmrealloc(ptr, i * sizeof(uint8_t));
    for (int j = 0; j < 42; ++j) {
      mu_check(ptr[j] == j);
    }
  }

  mmfree(ptr);
}

MU_TEST_SUITE(linear_tests) {
  mminit();
  MU_RUN_TEST(mmalloc_linear);
  MU_RUN_TEST(mmcalloc_linear);
  MU_RUN_TEST(mmrealloc_linear);
  mmdeinit();
}

MU_TEST(mmalloc_huge) {
  uint8_t **ptr;
  size_t n = 1024;

  mu_check((ptr = mmalloc(n * sizeof(uint8_t *))) != NULL);

  for (size_t i = 0; i < n; ++i) {
    mu_check((ptr[i] = mmalloc(1024)) != NULL);
  }
  
  for (size_t i = 0; i < n; ++i) {
    mmfree(ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST(mmalloc_huge1) {
  uint8_t **ptr;
  size_t n = 1024;

  mu_check((ptr = mmalloc(n * sizeof(uint8_t *))) != NULL);

  for (size_t i = 0; i < n; ++i) {
    mu_check((ptr[i] = mmalloc(1 * (i + 1))) != NULL);
  }
  
  for (size_t i = 0; i < n; ++i) {
    mmfree(ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST(mmalloc_huge3) {
  uint8_t **ptr;
  size_t n = 1024;

  mu_check((ptr = mmalloc(n * sizeof(uint8_t *))) != NULL);

  for (size_t i = 0; i < n; ++i) {
    mu_check((ptr[i] = mmalloc(3 * (i + 1))) != NULL);
  }
  
  for (size_t i = 0; i < n; ++i) {
    mmfree(ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST(mmalloc_huge7) {
  uint8_t **ptr;
  size_t n = 1024;

  mu_check((ptr = mmalloc(n * sizeof(uint8_t *))) != NULL);

  for (size_t i = 0; i < n; ++i) {
    mu_check((ptr[i] = mmalloc(7 * (i + 1))) != NULL);
  }
  
  for (size_t i = 0; i < n; ++i) {
    mmfree(ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST(mmalloc_huge42) {
  uint8_t **ptr;
  size_t n = 1024;

  mu_check((ptr = mmalloc(n * sizeof(uint8_t *))) != NULL);

  for (size_t i = 0; i < n; ++i) {
    mu_check((ptr[i] = mmalloc(42 * (i + 1))) != NULL);
  }
  
  for (size_t i = 0; i < n; ++i) {
    mmfree(ptr[i]);
  }

  mmfree(ptr);
}

MU_TEST_SUITE(huge_tests) {
  mminit();
  MU_RUN_TEST(mmalloc_huge);
  MU_RUN_TEST(mmalloc_huge1);
  MU_RUN_TEST(mmalloc_huge3);
  MU_RUN_TEST(mmalloc_huge7);
  MU_RUN_TEST(mmalloc_huge42);
  mmdeinit();
}

int main(void) {
  MU_RUN_SUITE(powerof2_tests);
  MU_RUN_SUITE(linear_tests);
  MU_RUN_SUITE(huge_tests);
  MU_REPORT();
  return MU_EXIT_CODE;
}

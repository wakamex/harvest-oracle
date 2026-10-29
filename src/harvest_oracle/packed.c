// Fixed-width call scans. The Python decoder checks frame lengths before calling these functions.
#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum { WORDS = 42, SITE = 17 };

int capture_equal(const uint64_t *a, const uint64_t *b, size_t count, uint64_t lower, uint64_t upper) {
  for (size_t i = 0; i < count; i++, a += WORDS, b += WORDS) {
    if (memcmp(a, b, SITE * 8) || memcmp(a + SITE + 1, b + SITE + 1, (WORDS - SITE - 1) * 8))
      return 0;
    // A raw pointer may translate differently. Reject even holes in the bounding interval;
    // the full comparator decides those cases using the actual translation ranges.
    for (size_t j = 0; j < 8; j++)
      if (j != 1 && a[j] >= lower && a[j] < upper)
        return 0;
  }
  return 1;
}

int valid_names(const uint64_t *calls, size_t count, uint64_t names) {
  for (size_t i = 0; i < count; i++)
    if (calls[i * WORDS + 1] > names)
      return 0;
  return 1;
}

// Return lengths of adjacent equal (target, name) runs. No hashing or lossy summaries.
size_t target_runs(const uint64_t *calls, size_t count, uint64_t *runs) {
  size_t groups = 0;
  for (size_t i = 0; i < count;) {
    size_t end = i + 1;
    while (end < count && calls[end * WORDS] == calls[i * WORDS] && calls[end * WORDS + 1] == calls[i * WORDS + 1])
      end++;
    runs[groups++] = end - i;
    i = end;
  }
  return groups;
}

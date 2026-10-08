/* Freestanding stand-ins for the C library calls of revng_runtime_library.c, which is linked into a version
 * built from rev.ng's C with those calls renamed to oracle_*: the version has no C library, and the names must
 * not meet adapters of the program's own imports. */
#include <stddef.h>
#include <stdint.h>

void *oracle_memcpy(void *to, const void *from, size_t n) {
  unsigned char *t = to;
  const unsigned char *f = from;
  while (n--)
    *t++ = *f++;
  return to;
}

void *oracle_memmove(void *to, const void *from, size_t n) {
  unsigned char *t = to;
  const unsigned char *f = from;
  if (t < f)
    while (n--)
      *t++ = *f++;
  else
    while (n--)
      t[n] = f[n];
  return to;
}

void *oracle_memset(void *to, int value, size_t n) {
  unsigned char *t = to;
  while (n--)
    *t++ = (unsigned char)value;
  return to;
}

int oracle_bcmp(const void *a, const void *b, size_t n) {
  const unsigned char *x = a, *y = b;
  while (n--)
    if (*x++ != *y++)
      return 1;
  return 0;
}

void oracle_abort(void) { __builtin_trap(); }
int oracle_fputc(int c, void *stream) { return c; }
size_t oracle_fwrite(const void *data, size_t size, size_t count, void *stream) { return count; }
int oracle_vfprintf(void *stream, const char *format, void *arguments) { return 0; }
void *oracle_stderr;

/* glibc's character classes for ASCII, indexed from -128 as __ctype_b_loc's table is. */
static unsigned short classes[384];
static const unsigned short *classes_at = classes + 128;

const unsigned short **oracle___ctype_b_loc(void) {
  if (!classes[128 + '0']) {
    for (int c = 0; c < 128; c++) {
      unsigned short v = 0;
      int upper = c >= 'A' && c <= 'Z', lower = c >= 'a' && c <= 'z', digit = c >= '0' && c <= '9';
      int xdigit = digit || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
      int space = c == ' ' || (c >= '\t' && c <= '\r');
      int print = c >= ' ' && c < 127;
      v |= upper ? 0x100 : 0;
      v |= lower ? 0x200 : 0;
      v |= upper || lower ? 0x400 : 0;
      v |= digit ? 0x800 : 0;
      v |= xdigit ? 0x1000 : 0;
      v |= space ? 0x2000 : 0;
      v |= print ? 0x4000 : 0;
      v |= print && c != ' ' ? 0x8000 : 0;
      v |= c == ' ' || c == '\t' ? 0x1 : 0;
      v |= c < ' ' || c == 127 ? 0x2 : 0;
      v |= print && c != ' ' && !upper && !lower && !digit ? 0x4 : 0;
      v |= upper || lower || digit ? 0x8 : 0;
      classes[128 + c] = v;
    }
  }
  return &classes_at;
}

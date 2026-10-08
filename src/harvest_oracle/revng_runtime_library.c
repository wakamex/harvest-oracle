/* Wide-integer operations behind rev.ng's runtime-library.h macros.
 *
 * Values are size-byte little-endian two's-complement integers processed one
 * byte at a time; arithmetic wraps modulo 2^(8 * size). Scratch buffers have a
 * fixed capacity, so sizes outside 1..RR_MAX_SIZE are refused, as are
 * operations the target would fault on or leave undefined. */
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime-library.h"

#define RR_MAX_SIZE 64

static const uint8_t zero[RR_MAX_SIZE];

static _Noreturn void fail(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    fputs("rev.ng runtime: ", stderr);
    vfprintf(stderr, format, arguments);
    va_end(arguments);
    fputc('\n', stderr);
    abort();
}

static void check_size(size_t size)
{
    if (size == 0 || size > RR_MAX_SIZE)
        fail("unsupported %zu-byte value (limit %d bytes)", size, RR_MAX_SIZE);
}

static int sign(const uint8_t *a, size_t size)
{
    return a[size - 1] >> 7;
}

static int is_zero(const uint8_t *a, size_t size)
{
    return memcmp(a, zero, size) == 0;
}

static int compare(const uint8_t *a, const uint8_t *b, size_t size)
{
    for (size_t i = size; i-- > 0;)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}

/* a += (b ^ flip) + carry; flip = 0xFF with carry = 1 subtracts b. */
static void accumulate(uint8_t *a, const uint8_t *b, size_t size, uint8_t flip,
                       unsigned carry)
{
    for (size_t i = 0; i < size; i++) {
        carry += a[i] + (uint8_t)(b[i] ^ flip);
        a[i] = (uint8_t)carry;
        carry >>= 8;
    }
}

static void negate(uint8_t *a, size_t size)
{
    for (size_t i = 0; i < size; i++)
        a[i] = (uint8_t)~a[i];
    accumulate(a, zero, size, 0, 1);
}

/* Shifts walk away from the bytes they still read, so they work in place. */
static void shift_left(uint8_t *a, size_t size, size_t amount)
{
    size_t bytes = amount / 8, bits = amount % 8;
    for (size_t i = size; i-- > 0;) {
        unsigned low = i > bytes ? a[i - bytes - 1] : 0;
        unsigned high = i >= bytes ? a[i - bytes] : 0;
        a[i] = (uint8_t)((high << 8 | low) << bits >> 8);
    }
}

static void shift_right(uint8_t *a, size_t size, size_t amount, uint8_t fill)
{
    size_t bytes = amount / 8, bits = amount % 8;
    for (size_t i = 0; i < size; i++) {
        unsigned low = i + bytes < size ? a[i + bytes] : fill;
        unsigned high = i + bytes + 1 < size ? a[i + bytes + 1] : fill;
        a[i] = (uint8_t)((high << 8 | low) >> bits);
    }
}

/* Amounts of 8 * size or more saturate there, which shifts every bit out. */
static size_t shift_amount(const uint8_t *a, size_t size)
{
    size_t amount = 0;
    for (size_t i = size; i-- > 0;) {
        amount = amount * 256 + a[i];
        if (amount >= 8 * size)
            return 8 * size;
    }
    return amount;
}

/* Restoring long division on magnitudes, then C's truncating signs: the
 * quotient is negative when the operand signs differ and the remainder takes
 * the dividend's sign. Outputs may alias the inputs but not each other. */
static void divide(uint8_t *quotient, uint8_t *remainder,
                   const uint8_t *dividend, const uint8_t *divisor, size_t size,
                   int is_signed)
{
    uint8_t n[RR_MAX_SIZE], d[RR_MAX_SIZE];
    check_size(size);
    memcpy(n, dividend, size);
    memcpy(d, divisor, size);
    if (is_zero(d, size))
        fail("division by zero");
    int n_negative = is_signed && sign(n, size);
    int d_negative = is_signed && sign(d, size);
    if (n_negative)
        negate(n, size);
    if (d_negative)
        negate(d, size);

    memset(quotient, 0, size);
    memset(remainder, 0, size);
    /* The remainder never exceeds the dividend bits consumed so far, so
     * shifting it cannot overflow. */
    for (size_t bit = 8 * size; bit-- > 0;) {
        shift_left(remainder, size, 1);
        remainder[0] |= (n[bit / 8] >> bit % 8) & 1;
        if (compare(remainder, d, size) >= 0) {
            accumulate(remainder, d, size, 0xFF, 1);
            quotient[bit / 8] |= (uint8_t)(1u << bit % 8);
        }
    }

    /* Only MIN / -1 gives a same-sign quotient with the sign bit set. */
    if (is_signed && n_negative == d_negative && sign(quotient, size))
        fail("signed division overflow");
    if (n_negative != d_negative)
        negate(quotient, size);
    if (n_negative)
        negate(remainder, size);
}

static unsigned digit_value(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 16;
}

/* An optional u and l or ll suffix in either order, then only blanks. */
static int valid_suffix(const char *p)
{
    int has_u = 0, has_l = 0;
    for (;;) {
        if (!has_u && (*p == 'u' || *p == 'U')) {
            has_u = 1;
            p++;
        } else if (!has_l && (*p == 'l' || *p == 'L')) {
            has_l = 1;
            p += p[1] == p[0] ? 2 : 1;
        } else {
            break;
        }
    }
    while (isspace((unsigned char)*p))
        p++;
    return *p == '\0';
}

void rr_imm_impl(void *out, size_t size, char const *literal)
{
    uint8_t *value = out;
    const char *p = literal;
    unsigned base = 10;
    int negative = 0;
    check_size(size);
    memset(value, 0, size);

    while (isspace((unsigned char)*p))
        p++;
    if (*p == '-' || *p == '+') {
        negative = *p++ == '-';
        while (isspace((unsigned char)*p))
            p++;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    } else if (p[0] == '0') {
        base = 8;
    }

    const char *digits = p;
    for (unsigned digit; (digit = digit_value(*p)) < base; p++) {
        unsigned carry = digit;
        for (size_t i = 0; i < size; i++) {
            carry += value[i] * base;
            value[i] = (uint8_t)carry;
            carry >>= 8;
        }
        if (carry)
            fail("literal '%s' does not fit in %zu bytes", literal, size);
    }
    if (p == digits || !valid_suffix(p))
        fail("malformed integer literal '%s'", literal);

    /* Negation leaves a magnitude above 2^(8 * size - 1) positive. */
    if (negative) {
        negate(value, size);
        if (!sign(value, size) && !is_zero(value, size))
            fail("literal '%s' does not fit in %zu bytes", literal, size);
    }
}

static void extend(const uint8_t *in, size_t in_size, uint8_t *out,
                   size_t out_size, int is_signed)
{
    check_size(in_size);
    check_size(out_size);
    if (out_size < in_size)
        fail("cannot extend %zu bytes to %zu bytes", in_size, out_size);
    uint8_t fill = is_signed && sign(in, in_size) ? 0xFF : 0;
    memmove(out, in, in_size);
    memset(out + in_size, fill, out_size - in_size);
}

void rr_zext_impl(const void *in, size_t in_size, void *out, size_t out_size)
{
    extend(in, in_size, out, out_size, 0);
}

void rr_sext_impl(const void *in, size_t in_size, void *out, size_t out_size)
{
    extend(in, in_size, out, out_size, 1);
}

void rr_truncate_impl(const void *in,
                      size_t in_size,
                      void *out,
                      size_t out_size)
{
    check_size(in_size);
    check_size(out_size);
    if (out_size > in_size)
        fail("cannot truncate %zu bytes to %zu bytes", in_size, out_size);
    memmove(out, in, out_size);
}

void rr_neg_impl(void *in_out, size_t size)
{
    check_size(size);
    negate(in_out, size);
}

void rr_add_impl(void *in_out, const void *in, size_t size)
{
    check_size(size);
    accumulate(in_out, in, size, 0, 0);
}

void rr_sub_impl(void *in_out, const void *in, size_t size)
{
    check_size(size);
    accumulate(in_out, in, size, 0xFF, 1);
}

void rr_mul_impl(void *in_out, const void *in, size_t size)
{
    const uint8_t *a = in_out, *b = in;
    uint8_t product[RR_MAX_SIZE] = {0};
    check_size(size);
    for (size_t i = 0; i < size; i++) {
        unsigned carry = 0;
        for (size_t j = 0; i + j < size; j++) {
            carry += product[i + j] + (unsigned)a[i] * b[j];
            product[i + j] = (uint8_t)carry;
            carry >>= 8;
        }
    }
    memcpy(in_out, product, size);
}

void rr_sdiv_impl(void *in_out, const void *in, size_t size)
{
    uint8_t remainder[RR_MAX_SIZE];
    divide(in_out, remainder, in_out, in, size, 1);
}

void rr_udiv_impl(void *in_out, const void *in, size_t size)
{
    uint8_t remainder[RR_MAX_SIZE];
    divide(in_out, remainder, in_out, in, size, 0);
}

void rr_srem_impl(void *in_out, const void *in, size_t size)
{
    uint8_t quotient[RR_MAX_SIZE];
    divide(quotient, in_out, in_out, in, size, 1);
}

void rr_urem_impl(void *in_out, const void *in, size_t size)
{
    uint8_t quotient[RR_MAX_SIZE];
    divide(quotient, in_out, in_out, in, size, 0);
}

void rr_shl_impl(void *in_out, const void *in, size_t size)
{
    check_size(size);
    shift_left(in_out, size, shift_amount(in, size));
}

void rr_shr_impl(void *in_out, const void *in, size_t size)
{
    check_size(size);
    shift_right(in_out, size, shift_amount(in, size), 0);
}

void rr_sar_impl(void *in_out, const void *in, size_t size)
{
    check_size(size);
    size_t amount = shift_amount(in, size);
    shift_right(in_out, size, amount, sign(in_out, size) ? 0xFF : 0);
}

void rr_bitnot_impl(void *in_out, size_t size)
{
    uint8_t *a = in_out;
    check_size(size);
    for (size_t i = 0; i < size; i++)
        a[i] = (uint8_t)~a[i];
}

void rr_bitand_impl(void *in_out, const void *in, size_t size)
{
    uint8_t *a = in_out;
    const uint8_t *b = in;
    check_size(size);
    for (size_t i = 0; i < size; i++)
        a[i] &= b[i];
}

void rr_bitor_impl(void *in_out, const void *in, size_t size)
{
    uint8_t *a = in_out;
    const uint8_t *b = in;
    check_size(size);
    for (size_t i = 0; i < size; i++)
        a[i] |= b[i];
}

void rr_bitxor_impl(void *in_out, const void *in, size_t size)
{
    uint8_t *a = in_out;
    const uint8_t *b = in;
    check_size(size);
    for (size_t i = 0; i < size; i++)
        a[i] ^= b[i];
}

void rr_inc_impl(void *in_out, size_t size)
{
    check_size(size);
    accumulate(in_out, zero, size, 0, 1);
}

void rr_dec_impl(void *in_out, size_t size)
{
    check_size(size);
    accumulate(in_out, zero, size, 0xFF, 0);
}

int rr_test_impl(const void *in, size_t size)
{
    check_size(size);
    return !is_zero(in, size);
}

int rr_ecmp_impl(const void *lhs, const void *rhs, size_t size)
{
    check_size(size);
    return memcmp(lhs, rhs, size) != 0;
}

int rr_scmp_impl(const void *lhs, const void *rhs, size_t size)
{
    check_size(size);
    int lhs_negative = sign(lhs, size), rhs_negative = sign(rhs, size);
    if (lhs_negative != rhs_negative)
        return rhs_negative - lhs_negative;
    return compare(lhs, rhs, size);
}

int rr_ucmp_impl(const void *lhs, const void *rhs, size_t size)
{
    check_size(size);
    return compare(lhs, rhs, size);
}

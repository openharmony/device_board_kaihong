/*
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
*/
///////////////////////////////////////////////////////////////////////////////
// \author (c) Marco Paland (info@paland.com)
//             2014-2019, PALANDesign Hannover, Germany
//
// \license The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// \brief Tiny printf, sprintf and (v)snprintf implementation, optimized for speed on
//        embedded systems with a very limited resources. These routines are thread
//        safe and reentrant!
//        Use this instead of the bloated standard/newlib printf cause these use
//        malloc for printf (and may not be thread safe).
//
///////////////////////////////////////////////////////////////////////////////

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include "usart.h"

// define this globally (e.g. gcc -DPRINTF_INCLUDE_CONFIG_H ...) to include the
// printf_config.h header file
// default: undefined
#ifdef PRINTF_INCLUDE_CONFIG_H
#include "printf_config.h"
#endif

// 'ntoa' conversion buffer size, this must be big enough to hold one converted
// numeric number including padded zeros (dynamically created on stack)
// default: 32 byte
#ifndef PRINTF_NTOA_BUFFER_SIZE
#define PRINTF_NTOA_BUFFER_SIZE 32U
#endif

// 'ftoa' conversion buffer size, this must be big enough to hold one converted
// float number including padded zeros (dynamically created on stack)
// default: 32 byte
#ifndef PRINTF_FTOA_BUFFER_SIZE
#define PRINTF_FTOA_BUFFER_SIZE 32U
#endif

// support for the floating point type (%f)
// default: activated
#ifndef PRINTF_DISABLE_SUPPORT_FLOAT
#define PRINTF_SUPPORT_FLOAT
#endif

// define the default floating point precision
// default: 6 digits
#ifndef PRINTF_DEFAULT_FLOAT_PRECISION
#define PRINTF_DEFAULT_FLOAT_PRECISION 6U
#endif

// define the largest float suitable to print with %f
// default: 1e9
#ifndef PRINTF_MAX_FLOAT
#define PRINTF_MAX_FLOAT 1e9
#endif

// support for the long long types (%llu or %p)
// default: activated
#ifndef PRINTF_DISABLE_SUPPORT_LONG_LONG
#define PRINTF_SUPPORT_LONG_LONG
#endif

// support for the ptrdiff_t type (%t)
// ptrdiff_t is normally defined in <stddef.h> as long or long long type
// default: activated
#ifndef PRINTF_DISABLE_SUPPORT_PTRDIFF_T
#define PRINTF_SUPPORT_PTRDIFF_T
#endif

// internal flag definitions
#define FLAGS_ZEROPAD (1U << 0U)
#define FLAGS_LEFT (1U << 1U)
#define FLAGS_PLUS (1U << 2U)
#define FLAGS_SPACE (1U << 3U)
#define FLAGS_HASH (1U << 4U)
#define FLAGS_UPPERCASE (1U << 5U)
#define FLAGS_CHAR (1U << 6U)
#define FLAGS_SHORT (1U << 7U)
#define FLAGS_LONG (1U << 8U)
#define FLAGS_LONG_LONG (1U << 9U)
#define FLAGS_PRECISION (1U << 10U)
#define FLAGS_ADAPT_EXP (1U << 11U)

// import float.h for DBL_MAX
#if defined(PRINTF_SUPPORT_FLOAT)
#include <float.h>
#endif

// output function type
typedef void (*out_fct_type)(char character, void *buffer, int idx, int maxlen);

// wrapper (used as buffer) for output function type
typedef struct {
    void (*fct)(char character, void *arg);
    void *arg;
} out_fct_wrap_type;

// internal buffer output
static inline void Gd32OutBuffer(char character, void *buffer, int idx, int maxlen)
{
    if (idx < maxlen) {
        ((char *)buffer)[idx] = character;
    }
}

// internal null output
static inline void Gd32OutNull(char character, void *buffer, int idx, int maxlen)
{
    (void)character;
    (void)buffer;
    (void)idx;
    (void)maxlen;
}

static inline void Gd32OutChar(char character, void *buffer, int idx, int maxlen)
{
    (void)buffer;
    (void)idx;
    (void)maxlen;
    if (character) {
        Gd32IoPutChar(character);
    }
}

// internal output function wrapper
static inline void Gd32OutFct(char character, void *buffer, int idx, int maxlen)
{
    (void)idx;
    (void)maxlen;
    if (character) {
        // buffer is the output fct pointer
        ((out_fct_wrap_type *)buffer)->fct(character, ((out_fct_wrap_type *)buffer)->arg);
    }
}

// internal secure strlen
// \return The length of the string (excluding the terminating 0) limited by 'maxsize'
static inline unsigned int Gd32Strnlen(const char *str, int maxsizein)
{
    int maxsize = maxsizein;
    const char *s;
    for (s = str; *s && maxsize--; ++s) { }
    return (unsigned int)(s - str);
}

// internal test if char is a digit (0-9)
// \return true if char is a digit
static inline bool _is_digit(char ch)
{
    return (ch >= '0') && (ch <= '9');
}

// internal ASCII string to unsigned int conversion
#define INTERVAL_ATOI 10U
static unsigned int _atoi(const char **str)
{
    unsigned int i = 0U;
    while (_is_digit(**str)) {
        i = i * INTERVAL_ATOI + (unsigned int)(*((*str)++) - '0');
    }
    return i;
}

// output the specified string in reverse, taking care of any zero-padding
static int Gd32OutRev(out_fct_type out, char *buffer, int idxin, int maxlen, const char *buf, int length,
                      unsigned int width, unsigned int flags)
{
    const int start_idx = idxin;
    int idx = idxin;
    int len = length;
    // pad spaces up to given width
    if (!(flags & FLAGS_LEFT) && !(flags & FLAGS_ZEROPAD)) {
        for (int i = len; i < width; i++) {
            out(' ', buffer, idx++, maxlen);
        }
    }

    // reverse string
    while (len) {
        out(buf[--len], buffer, idx++, maxlen);
    }

    // append pad spaces up to given width
    if (flags & FLAGS_LEFT) {
        while (idx - start_idx < width) {
            out(' ', buffer, idx++, maxlen);
        }
    }

    return idx;
}
#define HEXADECIMAL 16U
#define OCTONARY 8U
#define BINARY 2U

// internal itoa format
static int Gd32NtoaFormat(out_fct_type out, char *buffer, int idx, int maxlen, char *buf, int length, bool negative,
                          unsigned int base, unsigned int prec, unsigned int widthin, unsigned int flags)
{
    int len = length;
    int width = widthin;
    // pad leading zeros
    if (!(flags & FLAGS_LEFT)) {
        if (width && (flags & FLAGS_ZEROPAD) && (negative || (flags & (FLAGS_PLUS | FLAGS_SPACE)))) {
            width--;
        }
        while ((len < prec) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len++] = '0';
        }
        while ((flags & FLAGS_ZEROPAD) && (len < width) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len++] = '0';
        }
    }

    // handle hash
    if (flags & FLAGS_HASH) {
        if (!(flags & FLAGS_PRECISION) && len && ((len == prec) || (len == width))) {
            len--;
            if (len && (base == HEXADECIMAL)) {
                len--;
            }
        }
        if ((base == HEXADECIMAL) && !(flags & FLAGS_UPPERCASE) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len++] = 'x';
        } else if ((base == HEXADECIMAL) && (flags & FLAGS_UPPERCASE) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len++] = 'X';
        } else if ((base == BINARY) && (len < PRINTF_NTOA_BUFFER_SIZE)) {
            buf[len++] = 'b';
        }
        if (len < PRINTF_NTOA_BUFFER_SIZE) {
            buf[len++] = '0';
        }
    }

    if (len < PRINTF_NTOA_BUFFER_SIZE) {
        if (negative) {
            buf[len++] = '-';
        } else if (flags & FLAGS_PLUS) {
            buf[len++] = '+'; // ignore the space if the '+' exists
        } else if (flags & FLAGS_SPACE) {
            buf[len++] = ' ';
        }
    }

    return Gd32OutRev(out, buffer, idx, maxlen, buf, len, width, flags);
}

// internal itoa for 'long' type
static int Gd32NtoaLong(out_fct_type out, char *buffer, int idx, int maxlen, unsigned long valuein, bool negative,
                        unsigned long base, unsigned int prec, unsigned int width, unsigned int flagsin)
{
    char buf[PRINTF_NTOA_BUFFER_SIZE];
    int len = 0U;
    unsigned int flags = flagsin;
    unsigned long value = valuein;
    // no hash for 0 values
    if (!value) {
        flags &= ~FLAGS_HASH;
    }

    // write if precision != 0 and value is != 0
    if (!(flags & FLAGS_PRECISION) || value) {
        do {
            if (base == 0) {
                return 0;
            }
            const char digit = (char)(value % base);
            buf[len++] = digit < 0x0A ? '0' + digit : (flags & FLAGS_UPPERCASE ? 'A' : 'a') + digit - 0x0A;
            value /= base;
        } while (value && (len < PRINTF_NTOA_BUFFER_SIZE));
    }

    return Gd32NtoaFormat(out, buffer, idx, maxlen, buf, len, negative, (unsigned int)base, prec, width, flags);
}
#define MAX_DIGITS 9

// internal itoa for 'long long' type
#if defined(PRINTF_SUPPORT_LONG_LONG)
static int Gd32NtoaLongLong(out_fct_type out, char *buffer, int idx, int maxlen, unsigned long long valuein,
                            bool negative, unsigned long long base, unsigned int prec, unsigned int width,
                            unsigned int flagsin)
{
    char buf[PRINTF_NTOA_BUFFER_SIZE];
    int len = 0U;
    unsigned int flags = flagsin;
    unsigned long long value = valuein;
    // no hash for 0 values
    if (!value) {
        flags &= ~FLAGS_HASH;
    }

    // write if precision != 0 and value is != 0
    if (!(flags & FLAGS_PRECISION) || value) {
        do {
            if (base == 0) {
                return 0;
            }
            const char digit = (char)(value % base);
            buf[len++] = digit < (MAX_DIGITS + 1) ? '0' + digit
                                                  : (flags & FLAGS_UPPERCASE ? 'A' : 'a') + digit - (MAX_DIGITS + 1);
            value /= base;
        } while (value && (len < PRINTF_NTOA_BUFFER_SIZE));
    }

    return Gd32NtoaFormat(out, buffer, idx, maxlen, buf, len, negative, (unsigned int)base, prec, width, flags);
}
#endif // PRINTF_SUPPORT_LONG_LONG

#if defined(PRINTF_SUPPORT_FLOAT)

#define LIMIT_PRECISION 9U
// internal ftoa for fixed decimal floating point
static int Gd32Ftoa(out_fct_type out, char *buffer, int idx, int maxlen, double valuein, unsigned int precin,
                    unsigned int widthin, unsigned int flags)
{
    char buf[PRINTF_FTOA_BUFFER_SIZE];
    int len = 0U;
    double diff = 0.0;
    double value = valuein;
    unsigned int prec = precin;
    unsigned int width = widthin;
    // powers of 10
    static const double pow10[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000};

    // test for special values
    if (value != value) {
        return Gd32OutRev(out, buffer, idx, maxlen, "nan", sizeof("nan"), width, flags);
    }
    if (value < -DBL_MAX) {
        return Gd32OutRev(out, buffer, idx, maxlen, "fni-", sizeof("fni-"), width, flags);
    }
    if (value > DBL_MAX) {
        return Gd32OutRev(out, buffer, idx, maxlen, (flags & FLAGS_PLUS) ? "fni+" : "fni",
                          (flags & FLAGS_PLUS) ? sizeof("fni+") : sizeof("fni"), width, flags);
    }

    // test for very large values
    // standard printf behavior is to print EVERY whole number digit
    // -- which could be 100s of characters overflowing your buffers == bad
    if ((value > PRINTF_MAX_FLOAT) || (value < -PRINTF_MAX_FLOAT)) {
        return 0U;
    }

    // test for negative
    bool negative = false;
    if (value < 0) {
        negative = true;
        value = 0 - value;
    }

    // set default precision, if not set explicitly
    if (!(flags & FLAGS_PRECISION)) {
        prec = PRINTF_DEFAULT_FLOAT_PRECISION;
    }
    // limit precision to 9, cause a prec >= 10 can lead to overflow errors
    while ((len < PRINTF_FTOA_BUFFER_SIZE) && (prec > LIMIT_PRECISION)) {
        buf[len++] = '0';
        prec--;
    }

    int whole = (int)value;
    double tmp = (value - whole) * pow10[prec];
    unsigned long frac = (unsigned long)tmp;
    diff = tmp - frac;
#define MIN_PRECISION 0.5
    if (diff > MIN_PRECISION) {
        ++frac;
        // handle rollover, e.g. case 0.99 with prec 1 is 1.0
        if (frac >= pow10[prec]) {
            frac = 0;
            ++whole;
        }
    } else if (diff < MIN_PRECISION) {
    } else if ((frac == 0U) || (frac & 1U)) {
        // if halfway, round up if odd OR if last digit is 0
        ++frac;
    }

    if (prec == 0U) {
        diff = value - (double)whole;
        if ((!(diff < MIN_PRECISION) || (diff > MIN_PRECISION)) && (whole & 1)) {
            // exactly 0.5 and ODD, then round up
            // 1.5 -> 2, but 2.5 -> 2
            ++whole;
        }
    } else {
        unsigned int count = prec;
        // now do fractional part, as an unsigned number
        while (len < PRINTF_FTOA_BUFFER_SIZE) {
            --count;
            buf[len++] = (char)(0x30 + (frac % 0x0A));
            if (!(frac /= 0x0A)) {
                break;
            }
        }
        // add extra 0s
        while ((len < PRINTF_FTOA_BUFFER_SIZE) && (count-- > 0U)) {
            buf[len++] = '0';
        }
        if (len < PRINTF_FTOA_BUFFER_SIZE) {
            // add decimal
            buf[len++] = '.';
        }
    }

    // do whole part, number is reversed
    while (len < PRINTF_FTOA_BUFFER_SIZE) {
        buf[len++] = (char)(0x30 + (whole % 0x0A));
        if (!(whole /= 0x0A)) {
            break;
        }
    }

    // pad leading zeros
    if (!(flags & FLAGS_LEFT) && (flags & FLAGS_ZEROPAD)) {
        if (width && (negative || (flags & (FLAGS_PLUS | FLAGS_SPACE)))) {
            width--;
        }
        while ((len < width) && (len < PRINTF_FTOA_BUFFER_SIZE)) {
            buf[len++] = '0';
        }
    }

    if (len < PRINTF_FTOA_BUFFER_SIZE) {
        if (negative) {
            buf[len++] = '-';
        } else if (flags & FLAGS_PLUS) {
            buf[len++] = '+'; // ignore the space if the '+' exists
        } else if (flags & FLAGS_SPACE) {
            buf[len++] = ' ';
        }
    }

    return Gd32OutRev(out, buffer, idx, maxlen, buf, len, width, flags);
}

#endif // PRINTF_SUPPORT_FLOAT

// internal vsnprintf
static int Gd32Vsnintf(out_fct_type outin, char *buffer, const int maxlen, const char *formatin, va_list va)
{
    unsigned int flags, width, precision, n;
    int idx = 0U;
    const char *format = formatin;
    out_fct_type out = outin;
    if (!buffer) {
        // use null output function
        out = Gd32OutNull;
    }

    while (*format) {
        // format specifier?  %[flags][width][.precision][length]
        if (*format != '%') {
            // no
            out(*format, buffer, idx++, maxlen);
            format++;
            continue;
        } else {
            // yes, evaluate it
            format++;
        }

        // evaluate flags
        flags = 0U;
        do {
            switch (*format) {
                case '0':
                    flags |= FLAGS_ZEROPAD;
                    format++;
                    n = 1U;
                    break;
                case '-':
                    flags |= FLAGS_LEFT;
                    format++;
                    n = 1U;
                    break;
                case '+':
                    flags |= FLAGS_PLUS;
                    format++;
                    n = 1U;
                    break;
                case ' ':
                    flags |= FLAGS_SPACE;
                    format++;
                    n = 1U;
                    break;
                case '#':
                    flags |= FLAGS_HASH;
                    format++;
                    n = 1U;
                    break;
                default:
                    n = 0U;
                    break;
            }
        } while (n);

        // evaluate width field
        width = 0U;
        if (_is_digit(*format)) {
            width = _atoi(&format);
        } else if (*format == '*') {
            const int w = va_arg(va, int);
            if (w < 0) {
                flags |= FLAGS_LEFT; // reverse padding
                width = (unsigned int)-w;
            } else {
                width = (unsigned int)w;
            }
            format++;
        }

        // evaluate precision field
        precision = 0U;
        if (*format == '.') {
            flags |= FLAGS_PRECISION;
            format++;
            if (_is_digit(*format)) {
                precision = _atoi(&format);
            } else if (*format == '*') {
                const int prec = (int)va_arg(va, int);
                precision = prec > 0 ? (unsigned int)prec : 0U;
                format++;
            }
        }

        // evaluate length field
        switch (*format) {
            case 'l':
                flags |= FLAGS_LONG;
                format++;
                if (*format == 'l') {
                    flags |= FLAGS_LONG_LONG;
                    format++;
                }
                break;
            case 'h':
                flags |= FLAGS_SHORT;
                format++;
                if (*format == 'h') {
                    flags |= FLAGS_CHAR;
                    format++;
                }
                break;
#if defined(PRINTF_SUPPORT_PTRDIFF_T)
            case 't':
                flags |= (sizeof(ptrdiff_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format++;
                break;
#endif
            case 'j':
                flags |= (sizeof(intmax_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format++;
                break;
            case 'z':
                flags |= (sizeof(int) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG);
                format++;
                break;
            default:
                break;
        }

        // evaluate specifier
        switch (*format) {
            case 'd':
            case 'i':
            case 'u':
            case 'x':
            case 'X':
            case 'o':
            case 'b': {
                // set the base
                unsigned int base;
                if (*format == 'x' || *format == 'X') {
                    base = 16U;
                } else if (*format == 'o') {
                    base = 8U;
                } else if (*format == 'b') {
                    base = 2U;
                } else {
                    base = 10U;
                    flags &= ~FLAGS_HASH; // no hash for dec format
                }
                // uppercase
                if (*format == 'X') {
                    flags |= FLAGS_UPPERCASE;
                }

                // no plus or space flag for u, x, X, o, b
                if ((*format != 'i') && (*format != 'd')) {
                    flags &= ~(FLAGS_PLUS | FLAGS_SPACE);
                }

                // ignore '0' flag when precision is given
                if (flags & FLAGS_PRECISION) {
                    flags &= ~FLAGS_ZEROPAD;
                }

                // convert the integer
                if ((*format == 'i') || (*format == 'd')) {
                    // signed
                    if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
                        const long long value = va_arg(va, long long);
                        idx = Gd32NtoaLongLong(out, buffer, idx, maxlen,
                                               (unsigned long long)(value > 0 ? value : 0 - value), value < 0, base,
                                               precision, width, flags);
#endif
                    } else if (flags & FLAGS_LONG) {
                        const long value = va_arg(va, long);
                        idx = Gd32NtoaLong(out, buffer, idx, maxlen, (unsigned long)(value > 0 ? value : 0 - value),
                                           value < 0, base, precision, width, flags);
                    } else {
                        const int value = (flags & FLAGS_CHAR)    ? (char)va_arg(va, int)
                                          : (flags & FLAGS_SHORT) ? (short int)va_arg(va, int)
                                                                  : va_arg(va, int);
                        idx = Gd32NtoaLong(out, buffer, idx, maxlen, (unsigned int)(value > 0 ? value : 0 - value),
                                           value < 0, base, precision, width, flags);
                    }
                } else {
                    // unsigned
                    if (flags & FLAGS_LONG_LONG) {
#if defined(PRINTF_SUPPORT_LONG_LONG)
                        idx = Gd32NtoaLongLong(out, buffer, idx, maxlen, va_arg(va, unsigned long long), false, base,
                                               precision, width, flags);
#endif
                    } else if (flags & FLAGS_LONG) {
                        idx = Gd32NtoaLong(out, buffer, idx, maxlen, va_arg(va, unsigned long), false, base, precision,
                                           width, flags);
                    } else {
                        const unsigned int value = (flags & FLAGS_CHAR) ? (unsigned char)va_arg(va, unsigned int)
                                                   : (flags & FLAGS_SHORT)
                                                       ? (unsigned short int)va_arg(va, unsigned int)
                                                       : va_arg(va, unsigned int);
                        idx = Gd32NtoaLong(out, buffer, idx, maxlen, value, false, base, precision, width, flags);
                    }
                }
                format++;
                break;
            }
#if defined(PRINTF_SUPPORT_FLOAT)
            case 'f':
            case 'F':
                if (*format == 'F') {
                    flags |= FLAGS_UPPERCASE;
                }
                idx = Gd32Ftoa(out, buffer, idx, maxlen, va_arg(va, double), precision, width, flags);
                format++;
                break;
#endif // PRINTF_SUPPORT_FLOAT
            case 'c': {
                unsigned int l = 1U;
                // pre padding
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out(' ', buffer, idx++, maxlen);
                    }
                }
                // char output
                out((char)va_arg(va, int), buffer, idx++, maxlen);
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out(' ', buffer, idx++, maxlen);
                    }
                }
                format++;
                break;
            }

            case 's': {
                const char *p = va_arg(va, char *);
                if (!p) {
                    p = '(null)';
                }
                unsigned int l = Gd32Strnlen(p, precision ? precision : (int)-1);
                // pre padding
                if (flags & FLAGS_PRECISION) {
                    l = (l < precision ? l : precision);
                }
                if (!(flags & FLAGS_LEFT)) {
                    while (l++ < width) {
                        out(' ', buffer, idx++, maxlen);
                    }
                }
                // string output
                while ((*p != 0) && (!(flags & FLAGS_PRECISION) || precision--)) {
                    out(*(p++), buffer, idx++, maxlen);
                }
                // post padding
                if (flags & FLAGS_LEFT) {
                    while (l++ < width) {
                        out(' ', buffer, idx++, maxlen);
                    }
                }
                format++;
                break;
            }

            case 'p': {
                width = sizeof(void *) * 2U;
                flags |= FLAGS_ZEROPAD | FLAGS_UPPERCASE;
#if defined(PRINTF_SUPPORT_LONG_LONG)
                const bool is_ll = sizeof(uintptr_t) == sizeof(long long);
                if (is_ll) {
                    idx = Gd32NtoaLongLong(out, buffer, idx, maxlen, (uintptr_t)va_arg(va, void *), false, 16U,
                                           precision, width, flags);
                } else {
#endif
                    idx = Gd32NtoaLong(out, buffer, idx, maxlen, (unsigned long)((uintptr_t)va_arg(va, void *)), false,
                                       16U, precision, width, flags);
#if defined(PRINTF_SUPPORT_LONG_LONG)
                }
#endif
                format++;
                break;
            }

            case '%':
                out('%', buffer, idx++, maxlen);
                format++;
                break;

            default:
                out(*format, buffer, idx++, maxlen);
                format++;
                break;
        }
    }

    // termination
    out((char)0, buffer, idx < maxlen ? idx : maxlen - 1U, maxlen);

    // return written chars without terminating \0
    return (int)idx;
}

#include "cmsis_os2.h"
static osMutexId_t g_MuxUart = NULL;
int InitUartMutex(void)
{
    g_MuxUart = osMutexNew(NULL);
    if (g_MuxUart != NULL) {
        printf("\ncreat g_MuxUart=%d ok\n", g_MuxUart);
    }

    return 0;
}
int __wrap_printf(const char *format, ...)
{
    va_list va;
    if (g_MuxUart != NULL) {
        osMutexAcquire(g_MuxUart, osWaitForever);
    }
    va_start(va, format);
    char buffer[1];
    const int ret = Gd32Vsnintf(Gd32OutChar, buffer, (int)-1, format, va);
    va_end(va);
    if (g_MuxUart != NULL) {
        osMutexRelease(g_MuxUart);
    }
    return ret;
}

int __wrap_sprintf(char *buffer, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    const int ret = Gd32Vsnintf(Gd32OutBuffer, buffer, 0x7fffffff, format, va);
    va_end(va);
    return ret;
}

int __wrap_snprintf(char *buffer, int count, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    const int ret = Gd32Vsnintf(Gd32OutBuffer, buffer, count, format, va);
    va_end(va);
    return ret;
}

int __wrap_vprintf(const char *format, va_list va)
{
    char buffer[1];
    return Gd32Vsnintf(Gd32OutChar, buffer, 0x7fffffff, format, va);
}

int __wrap_vsnprintf(char *buffer, int count, const char *format, va_list va)
{
    return Gd32Vsnintf(Gd32OutBuffer, buffer, count, format, va);
}

int fctprintf(void (*out)(char character, void *arg), void *arg, const char *format, ...)
{
    va_list va;
    va_start(va, format);
    const out_fct_wrap_type out_fct_wrap = {out, arg};
    const int ret = Gd32Vsnintf(Gd32OutFct, (char *)(uintptr_t)&out_fct_wrap, (int)-1, format, va);
    va_end(va);
    return ret;
}

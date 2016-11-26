/*
    This code is public domain and comes with no warranty.
    You are free to do whatever you want with it. You can
    contact me at lolisamurai@tfwno.gf but don't expect any
    support.
    I hope you will find the code useful or at least
    interesting to read. Have fun!
    -----------------------------------------------------------
    This file is part of "junoms", a maplestory server emulator
*/

#define global_var static
#define internal static

#define array_count(a) (sizeof(a) / sizeof((a)[0]))
#define abs(v) ((v) < 0 ? -(v) : (v))

typedef i32 b32;
typedef double f64;

/* ------------------------------------------------------------- */

typedef intptr syscall_t;

void* syscall(syscall_t number);
void* syscall1(syscall_t number, void* arg);
void* syscall2(syscall_t number, void* arg1, void* arg2);

void* syscall3(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3);

void* syscall4(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4);

void* syscall5(
    syscall_t number,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4,
    void* arg5);

#ifdef I386
/* TODO: actually implement this properly */
i64 __divdi3(i64 a, i64 b) {
    return (i64)((f64)a / b);
}

u64 __udivdi3(u64 a, u64 b) {
    return (u64)((f64)a / b);
}
#endif

/* ------------------------------------------------------------- */

#define stdout 1
#define stderr 2

internal
intptr write(int fd, void const* data, intptr nbytes)
{
    return (intptr)
        syscall3(
            SYS_write,
            (void*)(intptr)fd,
            (void*)data,
            (void*)nbytes
        );
}

internal
intptr read(int fd, void* data, intptr nbytes)
{
    return (intptr)
        syscall3(
            SYS_read,
            (void*)(intptr)fd,
            data,
            (void*)nbytes
        );
}

internal
void close(int fd) {
    syscall1(SYS_close, (void*)(intptr)fd);
}

internal
intptr strlen(char* str)
{
    char* p;
    for(p = str; *p; ++p);
    return p - str;
}

internal
intptr fprln(int fd, char* str) {
    return write(fd, str, strlen(str)) + write(fd, "\n", 1);
}

internal
intptr fputs(int fd, char* str) {
    return write(fd, str, strlen(str));
}

internal
intptr puts(char* str) {
    return fputs(stdout, str);
}

internal
intptr prln(char* str) {
    return fprln(stdout, str);
}

internal
void die(char* msg)
{
    write(stderr, "ORERU: ", 7);
    fprln(stderr, msg);
}

/* ------------------------------------------------------------- */

#define AF_INET 2

#define SOCK_STREAM 1

typedef struct
{
    u16 family;
    u16 port; /* NOTE: this is big endian!!!!!!! use letobe16u */
    u32 addr;
    u8  zero[8];
}
sockaddr_in;

internal
u16 letobe16u(u16 v) {
    return (v << 8) | (v >> 8);
}

#ifdef SYS_socketcall
/* i386 multiplexes socket calls through socketcall */
#define SYS_SOCKET      1
#define SYS_BIND        2
#define SYS_CONNECT     3
#define SYS_LISTEN      4
#define SYS_ACCEPT      5
#define SYS_SHUTDOWN   13
#define SYS_SETSOCKOPT 14

internal
int socketcall(u32 call, void* args)
{
    return (int)(intptr)
        syscall2(
            SYS_socketcall,
            (void*)(intptr)call,
            args
        );
}
#endif

internal
int socket(u16 family, i32 type, i32 protocol)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_socket,
            (void*)(intptr)family,
            (void*)(intptr)type,
            (void*)(intptr)protocol
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)family;
    args[1] = (void*)(intptr)type;
    args[2] = (void*)(intptr)protocol;

    return socketcall(SYS_SOCKET, args);
#endif
}

internal
int bind(int sockfd, sockaddr_in const* addr)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_bind,
            (void*)(intptr)sockfd,
            (void*)addr,
            (void*)sizeof(sockaddr_in)
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)addr;
    args[2] = (void*)sizeof(sockaddr_in);

    return socketcall(SYS_BIND, args);
#endif
}

internal
int listen(int sockfd, int backlog)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall2(
            SYS_listen,
            (void*)(intptr)sockfd,
            (void*)(intptr)backlog
        );
#else
    void* args[2];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)(intptr)backlog;

    return socketcall(SYS_LISTEN, args);
#endif
}

internal
int accept(int sockfd, sockaddr_in const* addr)
{
    int addrlen = sizeof(sockaddr_in);
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall3(
            SYS_accept,
            (void*)(intptr)sockfd,
            (void*)addr,
            &addrlen
        );
#else
    void* args[3];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)addr;
    args[2] = &addrlen;

    return socketcall(SYS_ACCEPT, args);
#endif
}


#define IPPROTO_TCP 6
#define TCP_NODELAY 1

#if JMS_TCP_NODELAY
internal
int setsockopt(
    int sockfd,
    i32 level,
    i32 optname,
    void const* optval,
    u32 optlen)
{
#ifndef SYS_socketcall
    return (int)(intptr)
        syscall5(
            SYS_setsockopt,
            (void*)(intptr)sockfd,
            (void*)(intptr)level,
            (void*)(intptr)optname,
            (void*)optval,
            (void*)(intptr)optlen
        );
#else
    void* args[5];
    args[0] = (void*)(intptr)sockfd;
    args[1] = (void*)(intptr)level;
    args[2] = (void*)(intptr)optname;
    args[3] = (void*)optval;
    args[4] = (void*)(intptr)optlen;

    return socketcall(SYS_SETSOCKOPT, args);
#endif
}
#endif

/* forces a flush of the pending packets on the next send */
internal
int tcp_force_flush(int sockfd, b32 enabled) {
#if JMS_TCP_NODELAY
    return
        setsockopt(
            sockfd,
            ipproto_tcp,
            tcp_nodelay,
            &enabled,
            sizeof(b32)
        );
#else
    return 0;
#endif
}

/* ------------------------------------------------------------- */

internal
intptr getrandom(void* buf, intptr nbytes, u32 flags)
{
    return (intptr)
        syscall3(
            SYS_getrandom,
            buf,
            (void*)nbytes,
            (void*)(intptr)flags
        );
}

internal
i32 rand()
{
    i32 res;
    if (getrandom(&res, sizeof(i32), 0) != sizeof(i32)) {
        prln("getrandom failed in rand()");
    }
    return res;
}

internal
u8 rol(u8 v, u8 n)
{
    u8 msb;

    for(u8 i = 0; i < n; ++i)
    {
        msb = v & 0x80 ? 1 : 0;
        v <<= 1;
        v |= msb;
    }

    return v;
}

internal
u8 ror(u8 v, u8 n) /* 1kpp hype */
{
    u8 lsb;

    for(u8 i = 0; i < n; ++i)
    {
        lsb = v & 1 ? 0x80 : 0;
        v >>= 1;
        v |= lsb;
    }

    return v;
}

/* 100-ns intervals between jan 1 1601 and jan 1 1970 */
#define epoch_diff 116444736000000000LL

internal inline
u64 unix_msec_to_filetime(u64 unix_mseconds) {
    return epoch_diff + unix_mseconds * 10000;
}

internal inline
u64 unix_to_filetime(u64 unix_seconds) {
    return unix_msec_to_filetime(unix_seconds * 1000);
}

internal inline
u64 filetime_to_unix_msec(u64 filetime) {
    return (filetime - epoch_diff) / 10000;
}

internal inline
u64 filetime_to_unix(u64 filetime) {
    return filetime_to_unix_msec(filetime) / 1000;
}

#define CLOCK_REALTIME 0

typedef intptr time_t;
typedef intptr syscall_slong_t;

typedef struct
{
    time_t sec;
    syscall_slong_t nsec;
}
timespec;

internal
int clock_gettime(u32 clock_id, timespec* ts) {
    return (int)(intptr)
        syscall2(SYS_clock_gettime, (void*)(intptr)clock_id, ts);
}

internal
u64 unix_now_msec()
{
    timespec ts = {0};
    clock_gettime(CLOCK_REALTIME, &ts);
    return (u64)ts.sec * 1000 + (u64)ts.nsec / 1000000;
}

internal inline
u64 unix_now() {
    return unix_now_msec() / 1000;
}

internal inline
u64 filetime_now() {
    return unix_msec_to_filetime(unix_now_msec());
}

/* ------------------------------------------------------------- */

internal
char toupper(char c) {
    return (c >= 'a' && c <= 'z') ? c - 0x20 : c;
}

internal
char tolower(char c) {
    return (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
}

internal
void strdo(char* str, char (* func)(char c))
{
    for (; *str; ++str) {
        *str = func(*str);
    }
}

internal
intptr uitoa(
    u8 base,
    uintptr val,
    char* buf,
    intptr width,
    char filler)
{
    if (!base) {
        return 0;
    }

    char* p = buf;
    do
    {
        u8 digit = val % base;
        val /= base;
        *(p++) = "0123456789abcdef"[digit];
    }
    while(val);

    while (p - buf < width) {
        *(p++) = filler;
    }

    intptr res = p - buf;
    *p-- = 0;

    char c;
    while (p > buf)
    {
        /* flip the string */
        c = *p;
        *(p--) = *buf;
        *(buf++) = c;
    }

    return res;
}

#if 0
internal
intptr itoa(u8 base,
    intptr val,
    char* buf,
    intptr width,
    char filler)
{
    if (val < 0)
    {
        *(buf++) = '-';
        val = -val;
    }

    return uitoa(base, (uintptr)val, buf, width, filler);
}
#endif

internal
int atoui(char* str, u8 base, u64* res)
{
    if (base > 16) {
        return -1;
    }

    u64 prev = 0;

    *res = 0;

    for (; *str; ++str)
    {
        *res *= base;

        char c = tolower(*str);

        if (base <= 10 && c >= '0' && c <= '0' + (base - 1))
        {
            *res += (u64)(c - '0');
        }

        else if (base > 10 && c >= 'a' && c <= 'a' + (base - 11))
        {
            *res += (u64)(c - 'a') + 10;
        }

        if (*res < prev)
        {
            /* overflow */
            return -1;
        }

        prev = *res;
    }

    return 0;
}

# if 0
internal
int atoi(char* str, u8 base, i64* res)
{
    b32 negative = *str == '-';

    if (*str == '-' || *str == '+')
    {
        ++str;
    }

    u64 ures;
    if (atoui(str, base, &ures) < 0)
    {
        return -1;
    }

    if (ures > 0x7fffffffffffffffLL)
    {
        /* overflow */
        return -1;
    }

    *res = (i64)ures;

    if (negative) {
        *res = -*res;
    }

    return 0;
}
#endif

internal
void memecpy(void* dst, void* src, intptr nbytes)
{
    intptr i;

    if (nbytes / sizeof(intptr))
    {
        intptr* dst_chunks = (intptr*)dst;
        intptr* src_chunks = (intptr*)src;

        for (i = 0; i < nbytes / sizeof(intptr); ++i) {
            dst_chunks[i] = src_chunks[i];
        }

        nbytes %= sizeof(intptr);
        dst = &dst_chunks[i];
        src = &src_chunks[i];
    }

    u8* dst_bytes = (u8*)dst;
    u8* src_bytes = (u8*)src;

    for (i = 0; i < nbytes; ++i) {
        dst_bytes[i] = src_bytes[i];
    }
}

void memcpy(void* dst, void* src, intptr nbytes)
{
    /* on struct assignments, gcc automatically generates calls
       to memcpy. the function must be nonstatic for some reason */
    return memecpy(dst, src, nbytes);
}

internal
void memeset(void* dst, u8 value, intptr nbytes)
{
    intptr i;

    if (nbytes / sizeof(intptr))
    {
        intptr* dst_chunks = (intptr*)dst;
        intptr chunk;
        u8* raw_chunk = (u8*)&chunk;

        for (i = 0; i < sizeof(intptr); ++i) {
            raw_chunk[i] = value;
        }

        for (i = 0; i < nbytes / sizeof(intptr); ++i) {
            dst_chunks[i] = chunk;
        }

        nbytes %= sizeof(intptr);
        dst = &dst_chunks[i];
    }

    u8* dst_bytes = (u8*)dst;

    for (i = 0; i < nbytes; ++i) {
        dst_bytes[i] = value;
    }
}

internal
intptr strcpy(char* dst, char* src)
{
    intptr len = strlen(src);
    memecpy(dst, src, len);
    dst[len] = 0;
    return len;
}

internal
b32 streq(char* a, char* b)
{
    for (; *a && *b; ++a, ++b)
    {
        if (*a != *b) {
            return 0;
        }
    }

    return *a == *b;
}

internal
b32 strneq(char* a, char* b, intptr len)
{
    intptr i;

    for (i = 0; i < len && a[i] && b[i]; ++i)
    {
        if (a[i] != b[i]) {
            return 0;
        }
    }

    if (i == len) {
        --i;
    }

    return a[i] == b[i];
}

internal
char* strstr(char* haystack, char* needle)
{
    intptr len = strlen(needle);

    for(; *haystack; ++haystack)
    {
        if (strneq(haystack, needle, len)) {
            return haystack;
        }
    }

    return 0;
}

/* ------------------------------------------------------------- */

/* all the aes stuff is heavily based on TitanMS
   TODO: learn more about AES and clean up this code */

/* https://en.wikipedia.org/wiki/Rijndael_key_schedule */
global_var
u8 aes_rcon[256] =
{
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8,
    0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
    0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
    0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
    0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
    0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d,
    0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83,
    0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

/* https://en.wikipedia.org/wiki/Rijndael_S-box */
global_var
u8 aes_sbox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,

    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,

    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,

    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,

    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,

    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,

    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,

    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,

    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,

    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,

    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,

    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,

    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,

    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,

    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,

    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

internal
void aes_rotate(u8* word)
{
    u8 tmp = word[0];
    memecpy(word, word + 1, 3);
    word[3] = tmp;
}

internal
void aes_core(u8* word, intptr iter)
{
    aes_rotate(word);

    for (u8 i = 0; i < 4; ++i) {
        word[i] = aes_sbox[word[i]];
    }

    /* xor the rcon operation with the first byte */
    word[0] ^= aes_rcon[iter];
}

internal
void aes_expand_key(
    u8* key,
    u8* expanded_key,
    u8 size,
    intptr expanded_size)
{
    intptr current_size = 0;
    intptr rcon_iter = 1;

    u8 tmp[4];

    /* first bytes are just the initial key */
    memecpy(expanded_key, key, size);
    current_size += size;

    while (current_size < expanded_size)
    {
        /* save previous 4 bytes to a tmp buffer */
        memecpy(tmp, expanded_key + current_size - 4, 4);

        /* apply the core schedule to tmp every keysize bytes
           and increment rcon iteration */
        if (current_size % size == 0) {
            aes_core(tmp, rcon_iter++);
        }

        /* extra sbox for 256-bit keys */
        if (size == 32 && current_size % size == 16)
        {
            for (u8 i = 0; i < 4; ++i) {
                tmp[i] = aes_sbox[tmp[i]];
            }
        }

        /* xor tmp with the 4-byte block keysize bytes before
           the new expanded key. these will be the next four bytes
           stored in tmp.
           TODO: optimize this by xoring 4 bytes all at once, same
           for other parts of this aes implementation */
        for (u8 i = 0; i < 4; ++i)
        {
            expanded_key[current_size] =
                expanded_key[current_size - size] ^ tmp[i];

            ++current_size;
        }
    }
}

internal
void aes_sub_bytes(u8* state)
{
    for (u8 i = 0; i < 16; ++i) {
        state[i] = aes_sbox[state[i]];
    }
}

internal
void aes_shift_row(u8* state, u8 n)
{
    u8 tmp;

    /* basically rotates left by 8 bits */
    for (u8 i = 0; i < n; ++i)
    {
        tmp = state[0];
        memecpy(state, state + 1, 3);
        state[3] = tmp;
    }
}

internal
void aes_shift_rows(u8* state)
{
    for (u8 i = 0; i < 4; ++i) {
        aes_shift_row(state + i * 4, i);
    }
}

internal
void aes_add_round_key(u8* state, u8* round_key)
{
    for (u8 i = 0; i < 16; ++i) {
        state[i] ^= round_key[i];
    }
}

internal
u8 galois_multiplication(u8 a, u8 b)
{
    u8 p = 0;

    for (u8 i = 0; i < 8; ++i)
    {
        if (b & 1) {
            p ^= a;
        }

        u8 msb = a & 0x80;

        a <<= 1;

        if (msb) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return p;
}

internal
void aes_mix_column(u8* col)
{
    u8 cpy[4];
    memecpy(cpy, col, 4);

    col[0] =    galois_multiplication(cpy[0], 2) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 3);

    col[1] =    galois_multiplication(cpy[1], 2) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 1) ^
                galois_multiplication(cpy[2], 3);

    col[2] =    galois_multiplication(cpy[2], 2) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 1) ^
                galois_multiplication(cpy[3], 3);

    col[3] =    galois_multiplication(cpy[3], 2) ^
                galois_multiplication(cpy[2], 1) ^
                galois_multiplication(cpy[1], 1) ^
                galois_multiplication(cpy[0], 3);
}

internal
void aes_mix_columns(u8* state)
{
    u8 column[4];

    for (u8 i = 0; i < 4; ++i)
    {
        /* extract a column as an array */
        for (u8 j = 0; j < 4; ++j) {
            column[j] = state[j * 4 + i];
        }

        /* mix it */
        aes_mix_column(column);

        /* put it back in the matrix */
        for (u8 j = 0; j < 4; ++j) {
            state[j * 4 + i] = column[j];
        }
    }
}

internal
void aes_round(u8* state, u8* round_key)
{
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, round_key);
}

internal
void aes_create_round_key(u8* expanded_key, u8* round_key)
{
    for (u8 i = 0; i < 4; ++i)
    {
        for (u8 j = 0; j < 4; ++j) {
            round_key[i + j * 4] = expanded_key[i * 4 + j];
        }
    }
}

internal
void aes_main(u8* state, u8* expanded_key, intptr nrounds)
{
    u8 round_key[16];

    aes_create_round_key(expanded_key, round_key);
    aes_add_round_key(state, round_key);

    for (intptr i = 1; i < nrounds; ++i)
    {
        aes_create_round_key(expanded_key + i * 16, round_key);
        aes_round(state, round_key);
    }

    aes_create_round_key(expanded_key + nrounds * 16, round_key);
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_key);
}

internal
void aes_transform(u8* input, u8* output, u8* key, u8 key_size)
{
    u8 expanded_key[15 * 16];

    intptr nrounds;
    switch (key_size)
    {
    case 16:
        nrounds = 10;
        break;
    case 24:
        nrounds = 12;
        break;
    case 32:
        nrounds = 14;
        break;
    default:
        die("Invalid key_size passed to transform_aes");
        return;
    }

    intptr expanded_key_size = 16 * (nrounds + 1);
    u8 block[16];

    /* block is a column-major order 4x4 matrix, so we need to map
       our input to it correctly */
    for (u8 i = 0; i < 4; ++i)
    {
        for (u8 j = 0; j < 4; ++j) {
            block[i + j * 4] = input[i * 4 + j];
        }
    }

    aes_expand_key(key, expanded_key, key_size, expanded_key_size);
    aes_main(block, expanded_key, nrounds);

    /* unmap the matrix after the transformation back into the
       output buffer */
    for (u8 i = 0; i < 4; ++i)
    {
        for (u8 j = 0; j < 4; ++j) {
            output[i * 4 + j] = block[i + j * 4];
        }
    }
}

/* ------------------------------------------------------------- */

internal
void maple_aes_ofb_transform(u8* buf, u8* iv, intptr nbytes)
{
    u8 aeskey[32] = {
        0x13, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00,
        0xB4, 0x00, 0x00, 0x00,
        0x1B, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x00, 0x00,
        0x33, 0x00, 0x00, 0x00,
        0x52, 0x00, 0x00, 0x00,
    };

    u8 input[16] = {0};
    u8 output[16] = {0};
    u8 plaintext[16] = {0};
    u8 expanded_dong_i_mean_iv[16] = {0};

    for (u8 i = 0; i < 16; ++i) {
        expanded_dong_i_mean_iv[i] = iv[i%4];
    }

    /* first iteration (initializes input) */
    aes_transform(expanded_dong_i_mean_iv, output, aeskey, 32);

    for (u8 i = 0; i < 16; ++i) {
        plaintext[i] = output[i] ^ buf[i];
    }

    intptr chunks = nbytes / 16 + 1;

    if (chunks == 1)
    {
        memecpy(buf, plaintext, nbytes);
        return;
    }

    memecpy(buf, plaintext, 16);
    memecpy(input, output, 16);

    /* all chunks except the last one */
    for (intptr i = 1; i < chunks - 1; ++i)
    {
        aes_transform(input, output, aeskey, 32);

        intptr offset = i * 16;

        for (u8 j = 0; j < 16; ++j) {
            plaintext[j] = output[j] ^ buf[offset + j];
        }

        memecpy(buf + offset, plaintext, 16);
        memecpy(input, output, 16);
    }

    /* last chunk */
    aes_transform(input, output, aeskey, 32);

    intptr offset = (chunks - 1) * 16;

    for (u8 j = 0; j < 16; ++j) {
        plaintext[j] = output[j] ^ buf[offset + j];
    }

    memecpy(buf + offset, plaintext, nbytes % 16);
    memecpy(input, output, 16);
}

/* lol idk some fucked up key routine used to shuffle the iv */
internal
void maple_shuffle_iv(u8* iv)
{
    u8 shit[256] =
    {
        0xec, 0x3f, 0x77, 0xa4, 0x45, 0xd0, 0x71, 0xbf, 0xb7, 0x98,
        0x20, 0xfc, 0x4b, 0xe9, 0xb3, 0xe1, 0x5c, 0x22, 0xf7, 0x0c,
        0x44, 0x1b, 0x81, 0xbd, 0x63, 0x8d, 0xd4, 0xc3, 0xf2, 0x10,
        0x19, 0xe0, 0xfb, 0xa1, 0x6e, 0x66, 0xea, 0xae, 0xd6, 0xce,
        0x06, 0x18, 0x4e, 0xeb, 0x78, 0x95, 0xdb, 0xba, 0xb6, 0x42,
        0x7a, 0x2a, 0x83, 0x0b, 0x54, 0x67, 0x6d, 0xe8, 0x65, 0xe7,
        0x2f, 0x07, 0xf3, 0xaa, 0x27, 0x7b, 0x85, 0xb0, 0x26, 0xfd,
        0x8b, 0xa9, 0xfa, 0xbe, 0xa8, 0xd7, 0xcb, 0xcc, 0x92, 0xda,
        0xf9, 0x93, 0x60, 0x2d, 0xdd, 0xd2, 0xa2, 0x9b, 0x39, 0x5f,
        0x82, 0x21, 0x4c, 0x69, 0xf8, 0x31, 0x87, 0xee, 0x8e, 0xad,
        0x8c, 0x6a, 0xbc, 0xb5, 0x6b, 0x59, 0x13, 0xf1, 0x04, 0x00,
        0xf6, 0x5a, 0x35, 0x79, 0x48, 0x8f, 0x15, 0xcd, 0x97, 0x57,
        0x12, 0x3e, 0x37, 0xff, 0x9d, 0x4f, 0x51, 0xf5, 0xa3, 0x70,
        0xbb, 0x14, 0x75, 0xc2, 0xb8, 0x72, 0xc0, 0xed, 0x7d, 0x68,
        0xc9, 0x2e, 0x0d, 0x62, 0x46, 0x17, 0x11, 0x4d, 0x6c, 0xc4,
        0x7e, 0x53, 0xc1, 0x25, 0xc7, 0x9a, 0x1c, 0x88, 0x58, 0x2c,
        0x89, 0xdc, 0x02, 0x64, 0x40, 0x01, 0x5d, 0x38, 0xa5, 0xe2,
        0xaf, 0x55, 0xd5, 0xef, 0x1a, 0x7c, 0xa7, 0x5b, 0xa6, 0x6f,
        0x86, 0x9f, 0x73, 0xe6, 0x0a, 0xde, 0x2b, 0x99, 0x4a, 0x47,
        0x9c, 0xdf, 0x09, 0x76, 0x9e, 0x30, 0x0e, 0xe4, 0xb2, 0x94,
        0xa0, 0x3b, 0x34, 0x1d, 0x28, 0x0f, 0x36, 0xe3, 0x23, 0xb4,
        0x03, 0xd8, 0x90, 0xc8, 0x3c, 0xfe, 0x5e, 0x32, 0x24, 0x50,
        0x1f, 0x3a, 0x43, 0x8a, 0x96, 0x41, 0x74, 0xac, 0x52, 0x33,
        0xf0, 0xd9, 0x29, 0x80, 0xb1, 0x16, 0xd3, 0xab, 0x91, 0xb9,
        0x84, 0x7f, 0x61, 0x1e, 0xcf, 0xc5, 0xd1, 0x56, 0x3d, 0xca,
        0xf4, 0x05, 0xc6, 0xe5, 0x08, 0x49
    };

    u8 new_iv[4] = { 0xf2, 0x53, 0x50, 0xc6 };
    u32* new_iv_u32 = (u32*)new_iv;

    for (u8 i = 0; i < 4; ++i)
    {
        u8 input = iv[i];
        u8 value_input = shit[input];

        new_iv[0] += shit[new_iv[1]] - input;
        new_iv[1] -= new_iv[2] ^ value_input;
        new_iv[2] ^= shit[new_iv[3]] + input;
        new_iv[3] -= new_iv[0] - value_input;

        u32 full_iv = *new_iv_u32;
        u32 shift = full_iv >> 0x1D | full_iv << 0x03;

        *new_iv_u32 = shift;
    }

    memecpy(iv, new_iv, 4);
}

internal
void maple_encrypt(u8* buf, i32 nbytes)
{
    i32 j;
    u8 a, c;

    for (u8 i = 0; i < 3; ++i)
    {
        a = 0;

        for (j = nbytes; j > 0; --j)
        {
            c = buf[nbytes - j];
            c = rol(c, 3);
            c = (u8)((i32)c + j);
            c ^= a;
            a = c;
            c = ror(a, j);
            c ^= 0xFF;
            c += 0x48;
            buf[nbytes - j] = c;
        }

        a = 0;

        for (j = nbytes; j > 0; --j)
        {
            c = buf[j - 1];
            c = rol(c, 4);
            c = (u8)((i32)c + j);
            c ^= a;
            a = c;
            c ^= 0x13;
            c = ror(c, 3);
            buf[j - 1] = c;
        }
    }
}

internal
void maple_decrypt(u8* buf, i32 nbytes)
{
    i32 j;
    u8 a, b, c;

    for (u8 i = 0; i < 3; ++i)
    {
        a = 0;
        b = 0;

        for (j = nbytes; j > 0; --j)
        {
            c = buf[j - 1];
            c = rol(c, 3);
            c ^= 0x13;
            a = c;
            c ^= b;
            c = (u8)((i32)c - j);
            c = ror(c, 4);
            b = a;
            buf[j - 1] = c;
        }

        a = 0;
        b = 0;

        for (j = nbytes; j > 0; --j)
        {
            c = buf[nbytes - j];
            c -= 0x48;
            c ^= 0xFF;
            c = rol(c, j);
            a = c;
            c ^= b;
            c = (u8)((i32)c - j);
            c = ror(c, 3);
            b = a;
            buf[nbytes - j] = c;
        }
    }
}

#define MAPLE_VERSION 62
#define MAPLE_ENCRYPTED_HDR_SIZE 4

internal
u32 maple_encrypted_hdr(u8* iv, u16 nbytes)
{
    /* the lowest 16 bits are the high part of the send IV,
       xored with ffff - mapleversion or -(mapleversion + 1).

       the highest 16 bits are the low part xored with the size of
       the packet to obtain the packet size we simply hor the low
       part with the high part again */

    u16* high_iv = (u16*)(iv + 2);
    u16 lowpart = *high_iv;

    u16 version = MAPLE_VERSION;
    version = 0xFFFF - version;
    lowpart ^= version;

    u16 hipart = lowpart ^ nbytes;

    return (u32)lowpart | ((u32)hipart << 16);
}

/* ------------------------------------------------------------- */

internal
void p_encode1(u8** p, u8 v) {
    *(*p)++ = v;
}

internal
void p_append(u8** p, void* buf, intptr nbytes)
{
    memecpy(*p, buf, nbytes);
    *p += nbytes;
}

internal
void p_encode2(u8** p, u16 v) {
    p_append(p, &v, 2);
}

internal
void p_encode4(u8** p, u32 v) {
    p_append(p, &v, 4);
}

internal
void p_encode8(u8** p, u64 v) {
    p_append(p, &v, 8);
}

internal
void p_encode_buf(u8** p, u8* buf, u16 nbytes)
{
    p_encode2(p, nbytes);
    p_append(p, buf, nbytes);
}

internal
void p_encode_str(u8** p, char* str) {
    p_encode_buf(p, (u8*)str, strlen(str));
}

internal
u8* p_new(u16 hdr, u8* buf)
{
    u8* res = buf;
    p_encode2(&res, hdr);
    return res;
}

internal
u8 p_decode1(u8** p) {
    return *(*p)++;
}

internal
void p_get_bytes(u8** p, void* dst, intptr nbytes)
{
    memecpy(dst, *p, nbytes);
    *p += nbytes;
}

internal
u16 p_decode2(u8** p)
{
    u16 res;
    p_get_bytes(p, &res, 2);
    return res;
}

internal
u32 p_decode4(u8** p)
{
    u32 res;
    p_get_bytes(p, &res, 4);
    return res;
}

#if 0
internal
u64 p_decode8(u8** p)
{
    u64 res;
    p_get_bytes(p, &res, 8);
    return res;
}
#endif

internal
u16 p_decode_buf(u8** p, u8* buf)
{
    u16 len = p_decode2(p);
    p_get_bytes(p, buf, len);
    return len;
}

internal
void p_decode_str(u8** p, char* str)
{
    u16 len = p_decode_buf(p, (u8*)str);
    str[len] = 0;
}

/* ------------------------------------------------------------- */

global_var
char fmtbuf[0x10000]; /* used to format strings */

internal
void print_bytes(u8* buf, intptr nbytes)
{
    for (u32 i = 0; i < nbytes; ++i)
    {
        uitoa(16, (uintptr)buf[i], fmtbuf, 2, '0');
        strdo(fmtbuf, toupper);
        puts(fmtbuf);
        puts(" ");
    }
}

internal
void print_bytes_pre(char* prefix, u8* buf, intptr nbytes)
{
    puts("\n");
    puts(prefix);
    puts(" ");
    print_bytes(buf, nbytes);
    puts("\n");
}

#if JMS_DEBUG_SEND
#define dbg_send_print_packet print_bytes_pre
#else
#define dbg_send_print_packet(prefix, buf, nbytes)
#endif

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_SEND
#define dbg_send_print_encrypted_packet print_bytes_pre
#else
#define dbg_send_print_encrypted_packet(prefix, buf, nbytes)
#endif

#if JMS_DEBUG_RECV
#define dbg_recv_print_packet print_bytes_pre
#else
#define dbg_recv_print_packet(prefix, buf, nbytes)
#endif

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
#define dbg_recv_print_encrypted_packet print_bytes_pre
#else
#define dbg_recv_print_encrypted_packet(prefix, buf, nbytes)
#endif

/* ------------------------------------------------------------- */

internal
int tcp_socket(u16 port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        die("Failed to create socket");
        return sockfd;
    }

    sockaddr_in serv_addr = {0};
    serv_addr.family = AF_INET;
    serv_addr.port = letobe16u(port);

    if (bind(sockfd, &serv_addr) < 0) {
        die("Failed to bind address to socket");
        return -1;
    }

    if (listen(sockfd, 10) < 0) {
        die("Failed to listen on socket");
        return -1;
    }

    return sockfd;
}

typedef struct
{
    int fd;
    u8 iv_send[4];
    u8 iv_recv[4];
}
connection;

#define OUT_HANDSHAKE 0x000D

internal
int maple_accept(int sockfd, connection* con)
{
    prln("Waiting for client...");

    sockaddr_in client_addr = {0};
    con->fd = accept(sockfd, &client_addr);
    if (con->fd < 0) {
        die("Failed to accept connection from client");
        return -1;
    }

    prln("Client connected");

    if (getrandom(con->iv_recv, 4, 0) != 4 ||
        getrandom(con->iv_send, 4, 0) != 4)
    {
        die("Failed to generate random IV's");
        return -1;
    }

    /* build handshake packet */
    u8 handshake[15];
    u8* p = p_new(OUT_HANDSHAKE, handshake);
    p_encode4(&p, MAPLE_VERSION); /* maple version */
    p_append(&p, con->iv_recv, 4);
    p_append(&p, con->iv_send, 4);
    p_encode1(&p, 8); /* region */

    if (p - handshake > sizeof(handshake))
    {
        die("I'm retarded");
        return -1;
    }

    tcp_force_flush(con->fd, 1);

    if (write(con->fd, handshake, p - handshake) < 0)
    {
        die("Failed to send handshake packet");
        return -1;
    }

    tcp_force_flush(con->fd, 0);

#if JMS_DEBUG_SEND
    puts("Sent handshake packet: ");
    print_bytes(handshake, p - handshake);
    puts("\n");
#endif

    return 0;
}

internal
void maple_close(connection* con) {
    close(con->fd);
}

internal
intptr read_all(int fd, void* dst, intptr nbytes)
{
    intptr nread = 0;

    while (nread < nbytes)
    {
        intptr cb = read(fd, dst, nbytes);
        if (!cb) {
            prln("Client disconnected");
            return 0;
        }
        else if (cb < 0) {
            die("Socket error");
            return -1;
        }

        nread += cb;
    }

    return nread;
}

/* reads one entire maple packet
   NOTE: packets can be up to 0xFFFF bytes large, so make sure dst
   has enough room. */
internal
intptr maple_recv(connection* con, u8* dst)
{
    intptr nread;
    u32 encrypted_hdr;

    /* encrypted header */
    nread = read_all(
        con->fd,
        &encrypted_hdr,
        MAPLE_ENCRYPTED_HDR_SIZE
    );
    if (nread <= 0) {
        return nread;
    }

    /* decode packet length from header */
    u32 packet_len =
        (encrypted_hdr & 0x0000FFFF) ^
        (encrypted_hdr >> 16);

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
    puts("\n<- Encrypted header ");

    uitoa(16, encrypted_hdr, fmtbuf, 8, '0');
    puts(fmtbuf);

    puts(", packet length: ");

    uitoa(10, (uintptr)packet_len, fmtbuf, 0, 0);
    prln(fmtbuf);
#endif

    /* packet body */
    nread = read_all(con->fd, dst, packet_len);
    if (nread <= 0) {
        return nread;
    }

    dbg_recv_print_encrypted_packet(
        "<- Encrypted",
        dst,
        packet_len
    );

    maple_aes_ofb_transform(dst, con->iv_recv, packet_len);

    dbg_recv_print_encrypted_packet(
        "<- AES Decrypted",
        dst,
        packet_len
    );

    maple_decrypt(dst, packet_len);
    dbg_recv_print_packet("<-", dst, packet_len);

    maple_shuffle_iv(con->iv_recv);

    return nread;
}

/* sends one entire maple packet
   NOTE: this is ENCRYPTED send. to send unencrypted data,
   just use write. */
internal
intptr maple_send(connection* con, u8* packet, u16 nbytes)
{
    u32 encrypted_hdr = maple_encrypted_hdr(con->iv_send, nbytes);

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
    puts("\n-> Encrypted header ");

    uitoa(16, encrypted_hdr, fmtbuf, 8, '0');
    prln(fmtbuf);
#endif

    if (write(con->fd, &encrypted_hdr, MAPLE_ENCRYPTED_HDR_SIZE) !=
            MAPLE_ENCRYPTED_HDR_SIZE)
    {
        prln("W: failed to write encrypted header");
        return -1;
    }

    dbg_send_print_packet("->", packet, nbytes);

    maple_encrypt(packet, nbytes);

    dbg_send_print_encrypted_packet(
        "-> Maple Encrypted:",
        packet,
        nbytes
    );

    intptr pos = 0, first = 1;
    while (nbytes > pos) {
        /* TODO: clean the first flag up */
        if (nbytes > pos + 1460 - first * 4)
        {
            maple_aes_ofb_transform(
                packet,
                con->iv_send,
                1460 - first * 4
            );
        }
        else
        {
            maple_aes_ofb_transform(
                packet,
                con->iv_send,
                nbytes - pos
            );
        }

        pos += 1460 - first * 4;

        if (first) {
            first = 0;
        }
    }

    dbg_send_print_encrypted_packet(
        "-> Encrypted:",
        packet,
        nbytes
    );

    maple_shuffle_iv(con->iv_send);

    tcp_force_flush(con->fd, 1);
    intptr res = write(con->fd, packet, nbytes);
    tcp_force_flush(con->fd, 0);

    return res;
}

/* ------------------------------------------------------------- */

/* common */
#define OUT_PING 0x0011

#define IN_PONG 0x0018

/* login server */
#define IN_LOGIN_PASSWORD           0x0001
#define IN_AFTER_LOGIN              0x0009
#define IN_SERVER_LIST_REQUEST      0x000B
#define IN_SERVER_LIST_REREQUEST    0x0004
#define IN_SERVER_STATUS_REQUEST    0x0006
#define IN_VIEW_ALL_CHAR            0x000D
#define IN_RELOG                    0x001C
#define IN_CHARLIST_REQUEST         0x0005
#define IN_CHAR_SELECT              0x0013
#define IN_CHECK_CHAR_NAME          0x0015
#define IN_DELETE_CHAR              0x0017
#define IN_SET_GENDER               0x0008
#define IN_REGISTER_PIN             0x000A
#define IN_GUEST_LOGIN              0x0002

#define OUT_LOGIN_STATUS            0x0000
#define OUT_SERVER_STATUS           0x0003
#define OUT_PIN_OPERATION           0x0006
#define OUT_ALL_CHAR_LIST           0x0008
#define OUT_SERVER_LIST             0x000A
#define OUT_CHAR_LIST               0x000B
#define OUT_SERVER_IP               0x000C
#define OUT_CHAR_NAME_RESPONSE      0x000D
#define OUT_ADD_NEW_CHAR_ENTRY      0x000E
#define OUT_DELETE_CHAR_RESPONSE    0x000F
#define OUT_RELOG_RESPONSE          0x0016
#define OUT_GENDER_DONE             0x0004
#define OUT_PIN_ASSIGNED            0x0007

/* channel server */
#define IN_PLAYER_LOAD          0x0014
#define IN_PLAYER_UPDATE        0x00C0
#define IN_PLAYER_MOVE          0x0026
#define IN_PLAYER_INFO          0x0059

#define OUT_SERVER_MESSAGE      0x0041
#define OUT_CHANNEL_CHANGE      0x0010
#define OUT_STATS_UPDATE        0x001C
#define OUT_MAP_CHANGE          0x005C
#define OUT_PLAYER_INFO         0x003A
#define OUT_PLAYER_MOVEMENT     0x008D
#define OUT_PLAYER_SPAWN        0x0078

/* ------------------------------------------------------------- */

/* used to build packets everywhere */
global_var
u8 packet_buf[0x10000];

#if 0
internal
void send_ping(connection* con)
{
    u8* p = p_new(OUT_PING, packet_buf);
    maple_send(con, packet_buf, p - packet_buf);
}
#endif

/* TODO: associate this func with some kind of account struct
         later on */
internal
void send_auth_success_request_pin(
    connection* con,
    u32 account_id,
    u8 status,
    b32 is_admin,
    char* user,
    u64 creation_time)
{
    u8* p = p_new(OUT_LOGIN_STATUS, packet_buf);
    p_encode2(&p, 0);
    p_encode4(&p, 0);
    p_encode4(&p, account_id);
    p_encode1(&p, status);
    p_encode1(&p, is_admin ? 1 : 0);
    p_encode1(&p, is_admin ? 0x80 : 0); /* TODO: check these two */
    /*p_encode1(&p, gm_level > 0 ? 1 : 0); */
    p_encode_str(&p, user);
    p_encode1(&p, 0);

    /* TODO: quiet ban */
    p_encode1(&p, 0); /* reason */
    p_encode8(&p, 0); /* time */

    p_encode8(&p, unix_to_filetime(creation_time));
    p_encode4(&p, 1);
    /* non-zero hides "please select the world you would like to
       play in"
       not sure whether this packs more flags or not */

    maple_send(con, packet_buf, p - packet_buf);
}

#define LOGIN_ID_DELETED            3
#define LOGIN_INCORRECT_PASSWORD    4
#define LOGIN_NOT_REGISTERED        5
#define LOGIN_SYS_ERR_1             6
#define LOGIN_ALREADY_LOGGED        7
#define LOGIN_SYS_ERR_2             8
#define LOGIN_SYS_ERR_3             9
#define LOGIN_TOO_MANY_1            10
#define LOGIN_NOT_20                11
#define LOGIN_GM_WRONG_IP           13
#define LOGIN_WRONG_GATEWAY_1       14
#define LOGIN_TOO_MANY_2            15
#define LOGIN_UNVERIFIED_1          16
#define LOGIN_WRONG_GATEWAY_2       17
#define LOGIN_UNVERIFIED_2          21
#define LOGIN_LICENSE               23
#define LOGIN_EMS_NOTICE            25
#define LOGIN_TRIAL                 27

internal
void send_login_failed(connection* con, u16 reason)
{
    u8* p = p_new(OUT_LOGIN_STATUS, packet_buf);
    p_encode2(&p, reason);
    p_encode4(&p, 0);

    maple_send(con, packet_buf, p - packet_buf);
}

#define BAN_DELETED             0
#define BAN_HACKING             1
#define BAN_MACRO               2
#define BAN_AD                  3
#define BAN_HARASSMENT          4
#define BAN_PROFANE             5
#define BAN_SCAM                6
#define BAN_MISCONDUCT          7
#define BAN_ILLEGAL_TRANSACTION 8
#define BAN_ILLEGAL_CHARGING    9
#define BAN_TEMPORARY           10
#define BAN_IMPERSONATING_GM    11
#define BAN_ILLEGAL_PROGRAMS    12
#define BAN_MEGAPHONE           13
#define BAN_NULL                14

internal
void send_login_banned(
    connection* con,
    u8 reason,
    u64 expire_filetime)
{
    u8* p = p_new(OUT_LOGIN_STATUS, packet_buf);
    p_encode2(&p, 2);
    p_encode4(&p, 0);
    p_encode1(&p, reason);
    p_encode8(&p, expire_filetime);

    maple_send(con, packet_buf, p - packet_buf);
}

#define PIN_ACCEPTED    0
#define PIN_NEW         1
#define PIN_INVALID     2
#define PIN_SYS_ERR     3
#define PIN_ENTER       4

internal
void send_pin_operation(connection* con, u8 op)
{
    u8* p = p_new(OUT_PIN_OPERATION, packet_buf);
    p_encode1(&p, op);

    maple_send(con, packet_buf, p - packet_buf);
}

#define RIBBON_NO   0
#define RIBBON_E    1
#define RIBBON_N    2
#define RIBBON_H    3

/* TODO: associate these with the world_data struct? */

internal
u8* world_entry_begin(
    u8 id,
    char* name,
    u8 ribbon,
    char* event_msg,
    u16 exp_percent,
    u16 drop_percent,
    u8 max_channels)
{
    u8* p = p_new(OUT_SERVER_LIST, packet_buf);
    p_encode1(&p, id);
    p_encode_str(&p, name);
    p_encode1(&p, ribbon);
    p_encode_str(&p, event_msg);
    p_encode2(&p, exp_percent);
    p_encode2(&p, drop_percent);
    p_encode1(&p, 0);
    p_encode1(&p, max_channels);

    return p;
}

internal
void world_entry_encode_channel(
    u8** p,
    u8 worldid,
    u8 id,
    char* name,
    u32 pop)
{
    p_encode_str(p, name);
    p_encode4(p, pop);
    p_encode1(p, worldid);
    p_encode2(p, (u16)id);
}

typedef struct
{
    u16 x, y;
    char msg[64];
}
world_bubble;

internal
void world_entry_end(
    connection* con,
    u8* p,
    u16 nbubbles,
    world_bubble* bubbles)
{
    p_encode2(&p, nbubbles);

    for (u16 i = 0; i < nbubbles; ++i)
    {
        p_encode2(&p, bubbles[i].x);
        p_encode2(&p, bubbles[i].y);
        p_encode_str(&p, bubbles[i].msg);
    }

    maple_send(con, packet_buf, p - packet_buf);
}

internal
void send_end_of_world_list(connection* con)
{
    u8* p = p_new(OUT_SERVER_LIST, packet_buf);
    p_encode1(&p, 0xFF);
    maple_send(con, packet_buf, p - packet_buf);
}

#define SERVER_NORMAL   0
#define SERVER_HIGH     1
#define SERVER_FULL     2

internal
void send_server_status(connection* con, u16 status)
{
    u8* p = p_new(OUT_SERVER_STATUS, packet_buf);
    p_encode2(&p, status);
    maple_send(con, packet_buf, p - packet_buf);
}

internal
void send_all_chars_count(
    connection* con,
    u32 nworlds,
    u32 last_visible_char_slot)
{
    u8* p = p_new(OUT_ALL_CHAR_LIST, packet_buf);
    p_encode1(&p, 1);
    p_encode4(&p, nworlds);
    p_encode4(&p, last_visible_char_slot);
    maple_send(con, packet_buf, p - packet_buf);
}

internal
u8* all_chars_begin(u8 worldid, u8 nchars)
{
    u8* p = p_new(OUT_ALL_CHAR_LIST, packet_buf);
    p_encode1(&p, 0);
    p_encode1(&p, worldid);
    p_encode1(&p, nchars);

    return p;
}

internal
void all_chars_end(connection* con, u8* p) {
    maple_send(con, packet_buf, p - packet_buf);
}

internal
void send_relog_response(connection* con)
{
    u8* p = p_new(OUT_RELOG_RESPONSE, packet_buf);
    p_encode1(&p, 1);
    maple_send(con, packet_buf, p - packet_buf);
}

internal
u8* world_chars_begin(u8 nchars)
{
    u8* p = p_new(OUT_CHAR_LIST, packet_buf);
    p_encode1(&p, 0);
    p_encode1(&p, nchars);

    return p;
}

internal
void world_chars_end(connection* con, u8* p, u32 nmaxchars)
{
    p_encode4(&p, nmaxchars);
    maple_send(con, packet_buf, p - packet_buf);
}

internal
void send_char_name_response(connection* con, char* name, b32 used)
{
    u8* p = p_new(OUT_CHAR_NAME_RESPONSE, packet_buf);
    p_encode_str(&p, name);
    p_encode1(&p, used ? 1 : 0);

    maple_send(con, packet_buf, p - packet_buf);
}

internal
void send_connect_ip(
    connection* con,
    u8* ip,
    u16 port,
    u32 char_id)
{
    u8* p = p_new(OUT_SERVER_IP, packet_buf);
    p_encode2(&p, 0);
    p_append(&p, ip, 4);
    p_encode2(&p, port);
    p_encode4(&p, char_id);
    p_encode4(&p, 0);
    p_encode1(&p, 0);

    maple_send(con, packet_buf, p - packet_buf);
}

#define SERVER_MESSAGE_NOTICE           0
#define SERVER_MESSAGE_POPUP            1
#define SERVER_MESSAGE_MEGA             2
#define SERVER_MESSAGE_SMEGA            3
#define SERVER_MESSAGE_SCROLLING_HDR    4
#define SERVER_MESSAGE_PINK_TEXT        5
#define SERVER_MESSAGE_LIGHT_BLUE_TEXT  6

internal
void send_scrolling_header(connection* con, char* header)
{
    u8* p = p_new(OUT_SERVER_MESSAGE, packet_buf);
    p_encode1(&p, SERVER_MESSAGE_SCROLLING_HDR);
    p_encode1(&p, 1);
    p_encode_str(&p, header);

    maple_send(con, packet_buf, p - packet_buf);
}

/* ------------------------------------------------------------- */

#define INVALID_ID          ((u32)-1)
#define INVALID_MAP         999999999
#define ITEM_NO_EXPIRATION  3439756800LL

#define MAX_IGN_LEN         12
#define MAX_CHAR_SLOTS      36
#define MAX_WORLDS          15
#define MAX_CHANNELS        20
#define MIN_INV_SLOTS       24
#define MAX_INV_SLOTS       100
#define MIN_STORAGE_SLOTS   4
#define MAX_STORAGE_SLOTS   100
#define MAX_PETS            3
#define MAX_VIP_ROCK_MAPS   10
#define MAX_ROCK_MAPS       5
#define MAX_MOVEMENT_DATA   0xff

#define EQUIPPED_SLOTS 51
#define BUFF_BITMASK_BYTES 16

/* ------------------------------------------------------------- */

#define EQUIP_HELM                  1
#define EQUIP_FACE                  2
#define EQUIP_EYE                   3
#define EQUIP_EARRING               4
#define EQUIP_TOP                   5
#define EQUIP_BOTTOM                6
#define EQUIP_SHOE                  7
#define EQUIP_GLOVE                 8
#define EQUIP_CAPE                  9
#define EQUIP_SHIELD                10
#define EQUIP_WEAPON                11
#define EQUIP_RING1                 12
#define EQUIP_RING2                 13
#define EQUIP_PET_1                 14
#define EQUIP_RING3                 15
#define EQUIP_RING4                 16
#define EQUIP_PENDANT               17
#define EQUIP_MOUNT                 18
#define EQUIP_SADDLE                19
#define EQUIP_PET_COLLAR            20
#define EQUIP_PET_LABEL_RING_1      21
#define EQUIP_PET_ITEM_POUCH_1      22
#define EQUIP_PET_MESO_MAGNET_1     23
#define EQUIP_PET_AUTO_HP           24
#define EQUIP_PET_AUTO_MP           25
#define EQUIP_PET_WING_BOOTS_1      26
#define EQUIP_PET_BINOCULARS_1      27
#define EQUIP_PET_MAGIC_SCALES_1    28
#define EQUIP_PET_QUOTE_RING_1      29
#define EQUIP_PET_2                 30
#define EQUIP_PET_LABEL_RING_2      31
#define EQUIP_PET_QUOTE_RING_2      32
#define EQUIP_PET_ITEM_POUCH_2      33
#define EQUIP_PET_MESO_MAGNET_2     34
#define EQUIP_PET_WING_BOOTS_2      35
#define EQUIP_PET_BINOCULARS_2      36
#define EQUIP_PET_MAGIC_SCALES_2    37
#define EQUIP_PET_EQUIP_3           38
#define EQUIP_PET_LABEL_RING_3      39
#define EQUIP_PET_QUOTE_RING_3      40
#define EQUIP_PET_ITEM_POUCH_3      41
#define EQUIP_PET_MESO_MAGNET_3     42
#define EQUIP_PET_WING_BOOTS_3      43
#define EQUIP_PET_BINOCULARS_3      44
#define EQUIP_PET_MAGIC_SCALES_3    45
#define EQUIP_PET_ITEM_IGNORE_1     46
#define EQUIP_PET_ITEM_IGNORE_2     47
#define EQUIP_PET_ITEM_IGNORE_3     48
#define EQUIP_MEDAL                 49
#define EQUIP_BELT                  50

#define NINVENTORIES    5
#define INV_EQUIP       1
#define INV_USE         2
#define INV_SETUP       3
#define INV_ETC         4
#define INV_CASH        5

/* item_category */
#define ITEM_ARMOR_HELM         100
#define ITEM_ARMOR_FACE         101
#define ITEM_ARMOR_EYE          102
#define ITEM_ARMOR_EARRING      103
#define ITEM_ARMOR_TOP          104
#define ITEM_ARMOR_OVERALL      105
#define ITEM_ARMOR_BOTTOM       106
#define ITEM_ARMOR_SHOE         107
#define ITEM_ARMOR_GLOVE        108
#define ITEM_ARMOR_SHIELD       109
#define ITEM_ARMOR_CAPE         110
#define ITEM_ARMOR_RING         111
#define ITEM_ARMOR_PENDANT      112
#define ITEM_MEDAL              114
#define ITEM_WEAPON_1H_SWORD    130
#define ITEM_WEAPON_1H_AXE      131
#define ITEM_WEAPON_1H_MACE     132
#define ITEM_WEAPON_DAGGER      133
#define ITEM_WEAPON_WAND        137
#define ITEM_WEAPON_STAFF       138
#define ITEM_WEAPON_2H_SWORD    140
#define ITEM_WEAPON_2H_AXE      141
#define ITEM_WEAPON_2H_MACE     142
#define ITEM_WEAPON_SPEAR       143
#define ITEM_WEAPON_POLEARM     144
#define ITEM_WEAPON_BOW         145
#define ITEM_WEAPON_XBOW        146
#define ITEM_WEAPON_CLAW        147
#define ITEM_WEAPON_KNUCKLE     148
#define ITEM_WEAPON_GUN         149
#define ITEM_MOUNT              190
#define ITEM_ARROW              206
#define ITEM_STAR               207
#define ITEM_BULLET             233

/* item_data.type */
#define ITEM_EQUIP  1
#define ITEM_ITEM   2
#define ITEM_PET    3

/* equip_stats.flags and item_stats.flags */
#define ITEM_LOCK           0x0001
#define ITEM_SPIKES         0x0002
#define ITEM_COLD_PROTECT   0x0004
#define ITEM_UNTRADEABLE    0x0008

typedef struct
{
    u32 id;
    u8 type; /* equip, item or pet */
    u64 expire_time; /* in unix seconds */

    /* access the correct union member according to type unless you
       want the server to commit suicide by memory corruption */
    union
    {
        struct
        {
            /* specially made by <ign> */
            char maker[MAX_IGN_LEN + 1];
            u16 amount;
            u16 flags;
        }
        as_item;

        struct
        {
            char owner[MAX_IGN_LEN + 1];
            u8 upgrade_slots;
            u8 level;
            u16 str;
            u16 dex;
            u16 intt;
            u16 luk;
            u16 hp;
            u16 mp;
            u16 watk;
            u16 matk;
            u16 wdef;
            u16 mdef;
            u16 acc;
            u16 avoid;
            u16 hands;
            u16 speed;
            u16 jump;
            u16 flags;
        }
        as_equip;

        struct
        {
            u64 id; /* database id of the pet */
            char name[MAX_IGN_LEN + 1];
            u8 level;
            u16 closeness;
            u8 fullness;
        }
        as_pet;
    };
}
item_data;

internal inline
u32 item_category(u32 id) {
    return id / 10000;
}

internal inline
b32 item_is_rechargeable(u32 id)
{
    return item_category(id) == ITEM_BULLET ||
           item_category(id) == ITEM_STAR;
}

internal
void item_encode_as_pet(u8** p, item_data* item)
{
    p_encode1(p, item->type);
    p_encode4(p, item->id);
    p_encode1(p, 1); /* cash item = true */
    p_encode8(p, item->as_pet.id); /* cash id */
    p_encode8(p, 0); /* pretty sure this is a timestamp */
    p_append(p, item->as_pet.name, sizeof(item->as_pet.name));
    p_encode1(p, item->as_pet.level);
    p_encode2(p, item->as_pet.closeness);
    p_encode1(p, item->as_pet.fullness);
    p_encode8(p, unix_to_filetime(item->expire_time));
    p_encode4(p, 0);
    p_encode4(p, 0); /* trial pet expire time? */
}

internal
void item_encode(u8** p, item_data* item, i16 slot)
{
    if (slot)
    {
        /* equipped items have negative slot */
        slot = abs(slot);

        if (slot > 100) {
            slot -= 100;
        }

        p_encode1(p, (u8)(i8)slot);
    }

    if (item->type == ITEM_PET) {
        return item_encode_as_pet(p, item);
    }

    p_encode1(p, item->type);
    p_encode4(p, item->id);
    p_encode1(p, 0); /* not a cash item */
    p_encode8(p, unix_to_filetime(item->expire_time));

    if (item->type == ITEM_EQUIP)
    {
        /* equip */
        p_encode1(p, item->as_equip.upgrade_slots);
        p_encode1(p, item->as_equip.level);
        p_encode2(p, item->as_equip.str);
        p_encode2(p, item->as_equip.dex);
        p_encode2(p, item->as_equip.intt);
        p_encode2(p, item->as_equip.luk);
        p_encode2(p, item->as_equip.hp);
        p_encode2(p, item->as_equip.mp);
        p_encode2(p, item->as_equip.watk);
        p_encode2(p, item->as_equip.matk);
        p_encode2(p, item->as_equip.wdef);
        p_encode2(p, item->as_equip.mdef);
        p_encode2(p, item->as_equip.acc);
        p_encode2(p, item->as_equip.avoid);
        p_encode2(p, item->as_equip.hands);
        p_encode2(p, item->as_equip.speed);
        p_encode2(p, item->as_equip.jump);
        p_encode_str(p, item->as_equip.owner);
        p_encode2(p, item->as_equip.flags);
        p_encode8(p, 0); /* not sure what this is */

        return;
    }

    /* regular item */
    p_encode2(p, item->as_item.amount);
    p_append(p, item->as_item.maker, sizeof(item->as_item.maker));
    p_encode2(p, item->as_item.flags);

    if (item_is_rechargeable(item->id)) {
        p_encode8(p, 0); /* idk, could be some kind of id */
    }
}

/* ------------------------------------------------------------- */

#define SEX_OTOKONOKO   0
#define SEX_ONNANOKO    1 /* fucking weeb */

typedef struct
{
    u32 id;
    char name[MAX_IGN_LEN + 1];
    u8 gender;
    u8 skin;
    u32 face;
    u32 hair;
    u8 level;
    u16 job;
    u16 str;
    u16 dex;
    u16 intt;
    u16 luk;
    u16 hp;
    u16 maxhp;
    u16 mp;
    u16 maxmp;
    u16 ap;
    u16 sp;
    u32 exp;
    u16 fame;
    u32 map;
    u8 spawn;

    /* slots -1 to -51 translated to 0-50 */
    item_data equips[EQUIPPED_SLOTS];

    /* slots -101 to -151 translated to 0-50 */
    item_data cover_equips[EQUIPPED_SLOTS];

    /* inv number starts at zero, so subtract 1 from inv_equip,
       inv_use etc */
    u8 inv_capacity[NINVENTORIES];
    item_data inventory[NINVENTORIES][MAX_INV_SLOTS];
    /* slots start at zero */

    u32 world_rank;
    i32 world_rank_move;
    u32 job_rank;
    i32 job_rank_move;

    u8 buddy_list_size;
    i32 meso;

    u16 x, y;
    u8 stance;
    u16 foothold;
}
character_data;

internal
void char_encode_stats(u8** p, character_data* c)
{
    p_encode4(p, c->id);
    p_append(p, c->name, sizeof(c->name));
    p_encode1(p, c->gender);
    p_encode1(p, c->skin);
    p_encode4(p, c->face);
    p_encode4(p, c->hair);

    /* TODO: summoned pet id's here
       (I suppose the client will then send a request to summon
       given pet id's?) */
    for (u8 i = 0; i < MAX_PETS; ++i) {
        p_encode8(p, 0);
    }

    p_encode1(p, c->level);
    p_encode2(p, c->job);
    p_encode2(p, c->str);
    p_encode2(p, c->dex);
    p_encode2(p, c->intt);
    p_encode2(p, c->luk);
    p_encode2(p, c->hp);
    p_encode2(p, c->maxhp);
    p_encode2(p, c->mp);
    p_encode2(p, c->maxmp);
    p_encode2(p, c->ap);
    p_encode2(p, c->sp);
    p_encode4(p, c->exp);
    p_encode2(p, c->fame);
    p_encode4(p, 0); /* marriage flag */
    p_encode4(p, c->map);
    p_encode1(p, c->spawn);
    p_encode4(p, 0);
}

internal
void char_encode_look(u8** p, character_data* c)
{
    p_encode1(p, c->gender);
    p_encode1(p, c->skin);
    p_encode4(p, c->face);
    p_encode1(p, 0); /* TODO: check this */
    p_encode4(p, c->hair);

    /* normal equip slots that are not covered by other items */
    b32 visible_slots[EQUIPPED_SLOTS] = {0};

    /* visible equips (cash and stuff that covers normal equips) */
    for (u8 i = 0; i < EQUIPPED_SLOTS; ++i)
    {
        if (!c->cover_equips[i].type && !c->equips[i].type) {
            continue;
        }

        p_encode1(p, i);

        if (i == EQUIP_WEAPON && c->equips[i].type) {
            /* we want the non-cash weapon id here because cash
               weapon id is added later on in the packet */
            p_encode4(p, c->equips[i].id);
        }
        else
        {
            if (c->cover_equips[i].type)
            {
                /* display the cover item */
                p_encode4(p, c->cover_equips[i].id);
            }
            else {
                /* no cover item, so make the base equip visible */
                p_encode4(p, c->equips[i].id);
                visible_slots[i] = 1;
            }
        }
    }

    p_encode1(p, 0xFF); /* list terminator? */

    /* covered equips (normal equips that have covering items over
       them) */
    for (u8 i = 0; i < EQUIPPED_SLOTS; ++i)
    {
        if (!c->equips[i].type) {
            continue;
        }

        if (i == EQUIP_WEAPON) {
            /* cash weapon is after this item list */
            continue;
        }

        if (visible_slots[i]) {
            continue;
        }

        p_encode1(p, i);
        p_encode4(p, c->equips[i].id);
    }

    p_encode1(p, 0xFF); /* list terminator? */
    p_encode4(p, c->cover_equips[EQUIP_WEAPON].id);
    /* cash weapon */

    for (u8 i = 0; i < MAX_PETS; ++i) {
        p_encode4(p, 0); /* TODO: encode pet ITEM id's */
    }
}

internal
void char_encode(u8** p, character_data* c)
{
    char_encode_stats(p, c);
    char_encode_look(p, c);

    /* rankings */
    p_encode1(p, 1); /* enabled / disabled */
    p_encode4(p, c->world_rank);
    p_encode4(p, (u32)c->world_rank_move);
    p_encode4(p, c->job_rank);
    p_encode4(p, (u32)c->job_rank_move);
}

internal
void char_send_connect_data(
    connection* con,
    character_data* c,
    u8 channel_id)
{
    u8* p = p_new(OUT_MAP_CHANGE, packet_buf);
    p_encode4(&p, (u32)channel_id); /* why 4 bytes? */

    /* portal counter (the one used in map rushers) */
    p_encode1(&p, 1);

    /* flag that indicates that it's a connect packet */
    p_encode1(&p, 1);

#if 0
    /* some multiline message that disappears in like 3 seconds
       disabled because it's useless and it looks bad */

    p_encode2(&p, 2); /* line count */
    p_encode_str(&p, "Hello"); /* title */
    p_encode_str(&p, "I have no idea what this ui is");
    p_encode_str(&p, "but it disappears pretty fast");
#else
    p_encode2(&p, 0);
#endif

    /* rng seeds */
    p_encode4(&p, (u32)rand());
    p_encode4(&p, (u32)rand());
    p_encode4(&p, (u32)rand());

    p_encode8(&p, (u64)-1);
    char_encode_stats(&p, c);
    p_encode1(&p, c->buddy_list_size);

    p_encode4(&p, c->meso);

    /* max slots for each inventory */
    for (u8 i = 1; i <= NINVENTORIES; ++i) {
        p_encode1(&p, c->inv_capacity[i - 1]);
    }

    /* equipped items */
    for (u8 i = EQUIPPED_SLOTS - 1; i > 0; --i)
    {
        item_data* item = &c->equips[i];
        if (!item->type) {
            continue;
        }

        /* -50 to -1 (normal equips) */
        item_encode(&p, item, -(i16)i);
    }

    p_encode1(&p, 0);

    for (u8 i = EQUIPPED_SLOTS - 1; i > 0; --i)
    {
        item_data* item = &c->cover_equips[i];
        if (!item->type) {
            continue;
        }

        /* -150 to -101 (cash / cover items) */
        item_encode(&p, item, -(i16)i - 100);
    }

    p_encode1(&p, 0);

    /* items */
    for (u8 inv = 0; inv < NINVENTORIES; ++inv)
    {
        for (i16 i = 0; i < c->inv_capacity[inv]; ++i)
        {
            item_data* item = &c->inventory[inv][i];
            if (!item->type) {
                continue;
            }

            item_encode(&p, item, i + 1);
            /* slots in packets are 1-based, FUCK */
        }

        p_encode1(&p, 0); /* list terminator (zero slot) */
    }

    p_encode2(&p, 0); /* TODO: skills */
    p_encode2(&p, 0);

    p_encode2(&p, 0); /* TODO: quest info */
    p_encode2(&p, 0);

    p_encode2(&p, 0); /* minigame record list? */
    p_encode2(&p, 0); /* crush ring record list? */
    p_encode2(&p, 0); /* friendship ring record list? */
    p_encode2(&p, 0); /* marriage ring record list? */

    /* teleport rock locations TODO */
    for (u8 i = 0; i < MAX_ROCK_MAPS; ++i) {
        p_encode4(&p, INVALID_MAP);
    }

    /* vip teleport rock locations TODO */
    for (u8 i = 0; i < MAX_VIP_ROCK_MAPS; ++i) {
        p_encode4(&p, INVALID_MAP);
    }

    p_encode4(&p, 0);
    p_encode8(&p, filetime_now());

    maple_send(con, packet_buf, p - packet_buf);
}

internal
void char_send_info(
    connection* con,
    character_data* c,
    b32 is_self)
{
    u8* p = p_new(OUT_PLAYER_INFO, packet_buf);
    p_encode4(&p, c->id);
    p_encode1(&p, c->level);
    p_encode2(&p, c->job);
    p_encode2(&p, c->fame);
    p_encode1(&p, 0); /* married flag */
    p_encode_str(&p, "-"); /* guild */
    p_encode_str(&p, ""); /* guild alliance */
    p_encode1(&p, is_self ? 1 : 0);

    /* TODO: pets info */
    p_encode1(&p, 0);

    p_encode1(&p, 0); /* has mount ? */
    /* TODO: mount info */

    p_encode1(&p, 0); /* wishlist size */
    /* TODO: wishlist info */

    /* TODO: monster book */
    /* TODO: check if v62 has monster book (prob not) */
    p_encode4(&p, 0);
    p_encode4(&p, 0);
    p_encode4(&p, 0);
    p_encode4(&p, 0);
    p_encode4(&p, 0);

    maple_send(con, packet_buf, p - packet_buf);
}

internal
void char_send_spawn(connection* con, character_data* c)
{
    u8* p = p_new(OUT_PLAYER_SPAWN, packet_buf);
    p_encode4(&p, c->id);
    p_encode_str(&p, c->name);

    p_encode_str(&p, ""); /* guild */
    p_encode2(&p, 0); /* guild logo bg */
    p_encode1(&p, 0); /* guild logo bg color */
    p_encode2(&p, 0); /* guild logo */
    p_encode1(&p, 0); /* guild logo color */

    /* TODO: map buffs */

    /* this is a giant bitmask that contains which types of buffs
       are active */
    for (u8 i = 0; i < BUFF_BITMASK_BYTES; ++i) {
        p_encode1(&p, 0);
    }

    p_encode1(&p, 0);
    p_encode1(&p, 0);

    p_encode2(&p, c->job);
    char_encode_look(&p, c);
    p_encode4(&p, 0);
    p_encode4(&p, 0); /* item effect TODO */
    p_encode4(&p, 0); /* chair TODO */
    p_encode2(&p, c->x);
    p_encode2(&p, c->y);
    p_encode1(&p, c->stance);
    p_encode2(&p, c->foothold);
    p_encode1(&p, 0);

    /* TODO: summoned pets */
    p_encode1(&p, 0); /* summoned pet list terminator */

    /* TODO: mount info */
    p_encode4(&p, 0); /* mount level */
    p_encode4(&p, 0); /* mount exp */
    p_encode4(&p, 0); /* mount tiredness */

    p_encode1(&p, 0); /* player room TODO */
    p_encode1(&p, 0); /* chalkboard TODO */

    p_encode1(&p, 0); /* crush ring TODO */
    p_encode1(&p, 0); /* friends ring TODO */
    p_encode1(&p, 0); /* marriage ring TODO */

    p_encode1(&p, 0);
    p_encode1(&p, 0);
    p_encode1(&p, 0);

    maple_send(con, packet_buf, p - packet_buf);
}

/* ------------------------------------------------------------- */

#define MOVEMENT_NORMAL1        0
#define MOVEMENT_JUMP           1
#define MOVEMENT_KNOCKBACK      2
#define MOVEMENT_UNK1           3
#define MOVEMENT_TELEPORT       4
#define MOVEMENT_NORMAL2        5
#define MOVEMENT_FLASHJUMP      6
#define MOVEMENT_ASSAULTER      7
#define MOVEMENT_ASSASSINATE    8
#define MOVEMENT_RUSH           9
#define MOVEMENT_FALLING        10
#define MOVEMENT_CHAIR          11
#define MOVEMENT_EXCESSIVE_KB   12
#define MOVEMENT_RECOIL_SHOT    13
#define MOVEMENT_UNK2           14
#define MOVEMENT_JUMP_DOWN      15
#define MOVEMENT_WINGS          16
#define MOVEMENT_WINGS_FALLING  17

typedef struct
{
    u16 foothold;
    u16 x, y;
    u8 stance;
    u8 type;

    union
    {
        struct
        {
            u8 unk1;
        }
        as_falling;

        struct
        {
            u8 unk1;
            u16 unk2;
            u32 unk3;
        }
        as_wings,
        as_excessive_kb;

        struct
        {
            u16 unk1;
            u16 unk2;
            u16 unk3;
        }
        as_wings_falling;

        struct
        {
            u8 unk1;
            u32 unk2;
            u32 unk3;
        }
        as_unk2;

        struct
        {
            u32 unk1;
            u16 unk2;
        }
        as_normal1,
        as_normal2;

        struct
        {
            u16 unk1;
            u32 unk2;
            u16 unk3;
        }
        as_jump_down;

        struct
        {
            u16 unk1;
        }
        as_chair;

        struct
        {
            u32 unk1;
        }
        as_unk1,
        as_teleport,
        as_assaulter,
        as_assassinate,
        as_rush;
    };
}
movement_data;

internal
void movement_apply(
    movement_data* m,
    u8 nmovements,
    character_data* c)
{
    movement_data* last_mov = &m[nmovements - 1];
    c->x = last_mov->x;
    c->y = last_mov->y;
    c->stance = last_mov->stance;
    c->foothold = last_mov->foothold;
}

internal
u8 movement_decode(u8** p, movement_data* movements)
{
    u8 count = p_decode1(p);

    for (u8 i = 0; i < count; ++i)
    {
        movement_data* m = &movements[i];

        u8 type = p_decode1(p);
        m->type = type; /* TODO: check if same as stance */

        switch (type)
        {
            case MOVEMENT_FALLING:
                m->as_falling.unk1 = p_decode1(p);
                break;

            case MOVEMENT_WINGS:
            case MOVEMENT_EXCESSIVE_KB:
                m->as_wings.unk1 = p_decode1(p);
                m->as_wings.unk2 = p_decode2(p);
                m->as_wings.unk3 = p_decode4(p);
                break;

            case MOVEMENT_WINGS_FALLING:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->foothold = p_decode2(p);
                m->stance = p_decode1(p);
                m->as_wings_falling.unk1 = p_decode2(p);
                m->as_wings_falling.unk2 = p_decode2(p);
                m->as_wings_falling.unk3 = p_decode2(p);
                break;

            case MOVEMENT_UNK2:
                m->as_unk2.unk1 = p_decode1(p);
                m->as_unk2.unk2 = p_decode4(p);
                m->as_unk2.unk3 = p_decode4(p);
                break;

            case MOVEMENT_NORMAL1:
            case MOVEMENT_NORMAL2:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->as_normal1.unk1 = p_decode4(p);
                m->foothold = p_decode2(p);
                m->stance = p_decode1(p);
                m->as_normal1.unk2 = p_decode2(p);
                break;

            case MOVEMENT_JUMP:
            case MOVEMENT_KNOCKBACK:
            case MOVEMENT_FLASHJUMP:
            case MOVEMENT_RECOIL_SHOT:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->stance = p_decode1(p);
                m->foothold = p_decode2(p);
                break;

            case MOVEMENT_JUMP_DOWN:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->as_jump_down.unk1 = p_decode2(p);
                m->as_jump_down.unk2 = p_decode4(p);
                m->foothold = p_decode2(p);
                m->stance = p_decode1(p);
                m->as_jump_down.unk3 = p_decode2(p);
                break;

            case MOVEMENT_CHAIR:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->foothold = p_decode2(p);
                m->stance = p_decode1(p);
                m->as_chair.unk1 = p_decode2(p);
                break;

            case MOVEMENT_UNK1:
            case MOVEMENT_TELEPORT:
            case MOVEMENT_ASSAULTER:
            case MOVEMENT_ASSASSINATE:
            case MOVEMENT_RUSH:
                m->x = p_decode2(p);
                m->y = p_decode2(p);
                m->as_unk1.unk1 = p_decode4(p);
                m->stance = p_decode1(p);
                break;

            default:
                prln("W: invalid movement received");
                return 0;
        }
    }

    return count;
}

internal
void movement_encode(
    u8** p,
    movement_data* movements,
    u8 nmovements)
{
    p_encode1(p, nmovements);

    for (u8 i = 0; i < nmovements; ++i)
    {
        movement_data* m = &movements[i];
        p_encode1(p, m->type);

        switch (m->type)
        {
            case MOVEMENT_FALLING:
                p_encode1(p, m->as_falling.unk1);
                break;

            case MOVEMENT_WINGS:
            case MOVEMENT_EXCESSIVE_KB:
                p_encode1(p, m->as_wings.unk1);
                p_encode2(p, m->as_wings.unk2);
                p_encode4(p, m->as_wings.unk3);
                /* same mem layout as excessive_kb */
                break;

            case MOVEMENT_WINGS_FALLING:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode2(p, m->foothold);
                p_encode1(p, m->stance);
                p_encode2(p, m->as_wings_falling.unk1);
                p_encode2(p, m->as_wings_falling.unk2);
                p_encode2(p, m->as_wings_falling.unk3);
                break;

            case MOVEMENT_UNK2:
                p_encode1(p, m->as_unk2.unk1);
                p_encode4(p, m->as_unk2.unk2);
                p_encode4(p, m->as_unk2.unk3);
                break;

            case MOVEMENT_NORMAL1:
            case MOVEMENT_NORMAL2:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode4(p, m->as_normal1.unk1);
                p_encode2(p, m->foothold);
                p_encode1(p, m->stance);
                p_encode2(p, m->as_normal1.unk2);
                break;

            case MOVEMENT_JUMP:
            case MOVEMENT_KNOCKBACK:
            case MOVEMENT_FLASHJUMP:
            case MOVEMENT_RECOIL_SHOT:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode1(p, m->stance);
                p_encode2(p, m->foothold);
                break;

            case MOVEMENT_JUMP_DOWN:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode2(p, m->as_jump_down.unk1);
                p_encode4(p, m->as_jump_down.unk2);
                p_encode2(p, m->foothold);
                p_encode1(p, m->stance);
                p_encode2(p, m->as_jump_down.unk3);
                break;

            case MOVEMENT_CHAIR:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode2(p, m->foothold);
                p_encode1(p, m->stance);
                p_encode2(p, m->as_chair.unk1);
                break;

            case MOVEMENT_UNK1:
            case MOVEMENT_TELEPORT:
            case MOVEMENT_ASSAULTER:
            case MOVEMENT_ASSASSINATE:
            case MOVEMENT_RUSH:
                p_encode2(p, m->x);
                p_encode2(p, m->y);
                p_encode4(p, m->as_teleport.unk1);
                p_encode1(p, m->stance);
                break;

            default:
                prln("W: tried to send invalid movement");
                return;
        }
    }
}

internal
void movement_send(
    connection* con,
    movement_data* m,
    u8 nmovements,
    u32 player_id)
{
    u8* p = p_new(OUT_PLAYER_MOVEMENT, packet_buf);
    p_encode4(&p, player_id);
    p_encode4(&p, 0);
    movement_encode(&p, m, nmovements);

    maple_send(con, packet_buf, p - packet_buf);
}

/* ------------------------------------------------------------- */

typedef struct
{
    char name[64];
    u16 population;
    u16 port;
}
channel_data;

typedef struct
{
    char name[64];
    u8 ribbon;
    char message[64];
    u16 exp_percent;
    u16 drop_percent;
    char header[2000];

    u16 nchannels;
    channel_data channels[MAX_CHANNELS];
}
world_data;

/* ------------------------------------------------------------- */

/* this is all hardcoded stuff for testing purposes that will be
   removed once the server actually gets a database */

global_var
u16 hardcoded_nchars = 1;

global_var
character_data hardcoded_chars[MAX_CHAR_SLOTS];

internal
void init_hardcoded_chars()
{
    character_data* ch = hardcoded_chars;
    memeset(ch, 0, sizeof(hardcoded_chars));

    strcpy(ch->name, "weebweeb");
    ch->level = 200,
    ch->str = 1337,
    ch->dex = 1337,
    ch->intt = 1337,
    ch->luk = 1337,
    ch->hp = 6969,
    ch->maxhp = 6969,
    ch->mp = 727,
    ch->maxmp = 727,
    ch->fame = 1234;
    ch->map = 100000000;
    ch->hair = 30020;
    ch->face = 20000;
    ch->skin = 3;
    ch->id = 1;
    ch->world_rank = 1;
    ch->world_rank_move = 666;
    ch->job_rank = 1;
    ch->job_rank_move = 0;

    ch->meso = 123123123;

    ch->cover_equips[EQUIP_HELM].expire_time = ITEM_NO_EXPIRATION;
    ch->cover_equips[EQUIP_HELM].id = 1002193;
    ch->cover_equips[EQUIP_HELM].type = ITEM_EQUIP;

    ch->cover_equips[EQUIP_TOP].expire_time = ITEM_NO_EXPIRATION;
    ch->cover_equips[EQUIP_TOP].id = 1052040;
    ch->cover_equips[EQUIP_TOP].type = ITEM_EQUIP;

    ch->equips[EQUIP_TOP].expire_time = ITEM_NO_EXPIRATION;
    ch->equips[EQUIP_TOP].id = 1040002;
    ch->equips[EQUIP_TOP].type = ITEM_EQUIP;

    ch->equips[EQUIP_BOTTOM].expire_time = ITEM_NO_EXPIRATION;
    ch->equips[EQUIP_BOTTOM].id = 1060006;
    ch->equips[EQUIP_BOTTOM].type = ITEM_EQUIP;

    ch->equips[EQUIP_SHOE].expire_time = ITEM_NO_EXPIRATION;
    ch->equips[EQUIP_SHOE].id = 1072001;
    ch->equips[EQUIP_SHOE].type = ITEM_EQUIP;
    ch->equips[EQUIP_SHOE].as_equip.jump = 500;
    ch->equips[EQUIP_SHOE].as_equip.speed = 500;

    ch->equips[EQUIP_WEAPON].expire_time = ITEM_NO_EXPIRATION;
    ch->equips[EQUIP_WEAPON].id = 1302000;
    ch->equips[EQUIP_WEAPON].type = ITEM_EQUIP;

    ch->inventory[INV_EQUIP - 1][0]
        .expire_time = ITEM_NO_EXPIRATION;

    ch->inventory[INV_EQUIP - 1][0].id = 1302000;
    ch->inventory[INV_EQUIP - 1][0].type = ITEM_EQUIP;

    ch->inventory[INV_CASH - 1][0].expire_time =
        unix_now() + 90 * 24 * 60 * 60;

    ch->inventory[INV_CASH - 1][0].id = 5000000;
    ch->inventory[INV_CASH - 1][0].type = ITEM_PET;

    for (u8 i = 1; i <= NINVENTORIES; ++i) {
        ch->inv_capacity[i - 1] = MAX_INV_SLOTS;
    }
}

global_var
u8 hardcoded_nworlds = 1;

global_var
world_data hardcoded_worlds[MAX_WORLDS];

internal
void init_hardcoded_worlds()
{
    u16 baseport = 7200;

    world_data* w = hardcoded_worlds;

    strcpy(w->name, "Meme World 0");
    w->ribbon = RIBBON_NO;
    w->exp_percent = 100;
    w->drop_percent = 100;
#if JMS_NAVYSEALS
    strcpy(w->header,
        "What the fuck did you just fucking say about me, you "
        "little bitch? I'll have you know I graduated top of my "
        "class in the Navy Seals, and I've been involved in "
        "numerous secret raids on Al-Quaeda, and I have over 300 "
        "confirmed kills. I am trained in gorilla warfare and "
        "I'm the top sniper in the entire US armed forces. You "
        "are nothing to me but just another target. I will wipe "
        "you the fuck out with precision the likes of which has "
        "never been seen before on this Earth, mark my fucking "
        "words. You think you can get away with saying that shit "
        "to me over the Internet? Think again, fucker. As we speak"
        " I am contacting my secret network of spies across the "
        "USA and your IP is being traced right now so you better "
        "prepare for the storm, maggot. The storm that wipes out "
        "the pathetic little thing you call your life. You're "
        "fucking dead, kid. I can be anywhere, anytime, and I "
        "can kill you in over seven hundred ways, and that's "
        "just with my bare hands. Not only am I extensively "
        "trained in unarmed combat, but I have access to the "
        "entire arsenal of the United States Marine Corps and I "
        "will use it to its full extent to wipe your miserable "
        "ass off the face of the continent, you little shit. If "
        "only you could have known what unholy retribution your "
        "little \"clever\" comment was about to bring down upon "
        "you, maybe you would have held your fucking tongue. But "
        "you couldn't, you didn't, and now you're paying the "
        "price, you goddamn idiot.");
#else
    strcpy(w->header, "install gentoo");
#endif

    w->nchannels = 2;

    channel_data* c = w->channels;
    strcpy(c->name, "Meme World 0-1");
    c->population = 200;
    c->port = ++baseport;

    ++c;

    strcpy(c->name, "Meme World 0-2");
    c->population = 0;
    c->port = ++baseport;
}

global_var
char* hardcoded_user = "asdasd";

global_var
char* hardcoded_pass = "asdasd";

global_var
u32 hardcoded_account_id = 1;

global_var
u16 hardcoded_char_slots = 3;

/* ------------------------------------------------------------- */

/* these funcs temporarly get values from the hardcoded accounts
   and worlds, but they will shape the future api that gets stuff
   from the database */

internal
u8 get_worlds(world_data* worlds)
{
    /* this will be removed and world data will be received from
       worldserver */
    for (u8 i = 0; i < hardcoded_nworlds; ++i) {
        worlds[i] = hardcoded_worlds[i];
    }

    return hardcoded_nworlds;
}

internal
intptr account_by_user(char* user)
{
    if (streq(user, hardcoded_user)) {
        return hardcoded_account_id;
    }

    return 0;
}

internal
b32 account_check_password(u32 account_id, char* password)
{
    if (account_id != hardcoded_account_id) {
        prln("W: tried to check password of non-existing account");
        return 0;
    }

    return streq(password, hardcoded_pass);
}

internal
u16 char_slots(u32 account_id)
{
    if (account_id != hardcoded_account_id) {
        return 0;
    }

    return hardcoded_char_slots;
}

internal
u16 chars_by_world(
    u32 account_id,
    u8 world_id,
    character_data* chars)
{
    if (world_id != 0) {
        prln("W: tried to get chars for non-existing world");
        return 0;
    }

    if (account_id != hardcoded_account_id) {
        prln("W: tried to get chars for non-existing account");
        return 0;
    }

    if (chars)
    {
        for (u16 i = 0; i < hardcoded_nchars; ++i) {
            chars[i] = hardcoded_chars[i];
        }
    }

    return hardcoded_nchars;
}

internal
int char_by_id(u32 id, character_data* c)
{
    if (!id || id > hardcoded_nchars) {
        return -1;
    }

    *c = hardcoded_chars[id - 1];
    return 0;
}

/* ------------------------------------------------------------- */

typedef struct
{
    u32 account_id;
    char user[12];
    b32 logged_in;
    u8 world;
    u8 channel;
    u32 char_id;
    b32 in_game;
}
client_data;

/* NOTE: for testing purposes, the server currently only handle
         1 player at once */
internal
int login_server(
    int sockfd,
    client_data* client,
    world_data* dst_world)
{
#if JMS_DRAW_DICK
    u16 cx1 = 40, cy1 = 300;
    u16 cx2 = 40, cy2 = 190;
    u16 my = cy2 + (cy1 - cy2) / 2;
#endif

    world_bubble bubbles[]  = {
        { 100, 100, "install gentoo" },

#if JMS_DRAW_DICK
        { cx1 - 40, cy1, "@" },
        { cx1 - 25, cy1 + 30, "@" },
        { cx1 - 25, cy1 - 30, "@" },
        { cx1, cy1 - 40, "@" },
        { cx1, cy1 + 40, "@" },

        { cx1 + 40, cy1, "@" },
        { cx1 + 25, cy1 + 30, "@" },
        { cx1 + 25, cy1 - 30, "@" },

        { cx2 - 40, cy2, "@" },
        { cx2 - 25, cy2 + 30, "@" },
        { cx2 - 25, cy2 - 30, "@" },
        { cx2, cy2 - 40, "@" },
        { cx2, cy2 + 40, "@" },

        { cx2 + 40, cy2, "@" },
        { cx2 + 25, cy2 + 30, "@" },
        { cx2 + 25, cy2 - 30, "@" },

        { cx1 + 40, my - 30, "@" },
        { cx1 + 40, my + 30, "@" },
        { cx1 + 70, my - 30, "@" },
        { cx1 + 70, my + 30, "@" },
        { cx1 + 100, my - 30, "@" },
        { cx1 + 100, my + 30, "@" },
        { cx1 + 130, my - 30, "@" },
        { cx1 + 130, my + 30, "@" },
        { cx1 + 160, my - 30, "@" },
        { cx1 + 160, my + 30, "@" },
        { cx1 + 190, my - 30, "@" },
        { cx1 + 190, my + 30, "@" },
        { cx1 + 220, my - 10, "@" },
        { cx1 + 220, my + 10, "@" },
#endif
    };

    /* --- */

    world_data worlds[MAX_WORLDS];
    u8 nworlds = get_worlds(worlds);

    int retcode = 0;

    connection con = {0};
    if (maple_accept(sockfd, &con) < 0)
    {
        retcode = 1;
        goto cleanup;
    }

    while (1)
    {
        intptr nread = maple_recv(&con, packet_buf);
        retcode = nread < 0;
        if (nread <= 0) {
            goto cleanup;
        }

        u8* p = packet_buf;
        u16 hdr = p_decode2(&p);

        /* TODO: reduce indentation here */
        switch (hdr)
        {
        case IN_LOGIN_PASSWORD:
            p_decode_str(&p, fmtbuf);

            /* ignore retarded long usernames */
            if (strlen(fmtbuf) > sizeof(client->user) - 1)
            {
                send_login_failed(&con, LOGIN_NOT_REGISTERED);
                break;
            }

            client->account_id = account_by_user(fmtbuf);
            if (!client->account_id)
            {
                char* p = fmtbuf;
                for (; *p && *p < '0' && *p > '9'; ++p);

                if (strstr(fmtbuf, "error") == fmtbuf)
                {
                    u64 reason;

                    if (atoui(p, 10, &reason) < 0)
                    {
                        send_login_failed(
                            &con,
                            LOGIN_NOT_REGISTERED
                        );
                        break;
                    }

                    send_login_failed(&con, (u32)reason);
                }

                if (strstr(fmtbuf, "ban") == fmtbuf)
                {
                    u64 reason;

                    if (atoui(p, 10, &reason) < 0)
                    {
                        send_login_failed(
                            &con,
                            LOGIN_NOT_REGISTERED
                        );
                        break;
                    }

                    send_login_banned(
                        &con,
                        (u32)reason,
                        unix_to_filetime(
                            unix_now() + 2 * 365 * 24 * 60 * 60
                        )
                    );
                }

                else {
                    send_login_failed(&con, LOGIN_NOT_REGISTERED);
                }

                break;
            }

            strcpy(client->user, fmtbuf);

            /* password */
            p_decode_str(&p, fmtbuf);

            if (!account_check_password(
                    client->account_id,
                    fmtbuf))
            {
                send_login_failed(&con, LOGIN_INCORRECT_PASSWORD);
                break;
            }

            client->logged_in = 1;
            send_auth_success_request_pin(
                &con,
                client->account_id,
                0, 0, /* TODO */
                client->user,
                1441134000LL /* TODO */
            );
            break;
        }

        /* ----------------------------------------------------- */

        if (!client->logged_in) {
            continue;
        }

        switch (hdr)
        {
        case IN_AFTER_LOGIN:
            send_pin_operation(&con, PIN_ACCEPTED); /* FUCK pins */
            break;

        /* ----------------------------------------------------- */
        /* why the fuck are there 2 hdrs for this */
        case IN_SERVER_LIST_REQUEST:
        case IN_SERVER_LIST_REREQUEST:
        {
            for (u8 i = 0; i < hardcoded_nworlds; ++i)
            {
                world_data* world = &hardcoded_worlds[i];
                u8* p = world_entry_begin(
                    i,
                    world->name,
                    world->ribbon,
                    world->message,
                    world->exp_percent,
                    world->drop_percent,
                    world->nchannels
                );

                for (u8 j = 0; j < world->nchannels; ++j)
                {
                    channel_data* ch = &world->channels[j];
                    world_entry_encode_channel(
                        &p,
                        i,
                        j,
                        ch->name,
                        ch->population
                    );
                }

                world_entry_end(
                    &con,
                    p,
                    array_count(bubbles),
                    bubbles
                );
            }

            send_end_of_world_list(&con);
            break;
        }

        /* ----------------------------------------------------- */

        case IN_SERVER_STATUS_REQUEST:
        {
            client->world = p_decode1(&p);
            send_server_status(&con, SERVER_NORMAL);
            break;
        }

        /* ----------------------------------------------------- */

        case IN_VIEW_ALL_CHAR:
        {
            u16 nall_chars = 0;

            for (u8 i = 0; i < nworlds; ++i) {
                nall_chars +=
                    chars_by_world(
                        client->account_id,
                        client->world,
                        0
                    );
            }

            send_all_chars_count(
                &con,
                nall_chars,
                nall_chars + 3 - nall_chars % 3
            );

            u8* p = all_chars_begin(0, nall_chars);

            for (u8 i = 0; i < nworlds; ++i)
            {
                character_data chars[MAX_CHAR_SLOTS];
                u16 n =
                    chars_by_world(
                        client->account_id,
                        client->world,
                        chars
                    );

                for (u16 j = 0; j < n; ++j) {
                    char_encode(&p, &chars[i]);
                }
            }

            all_chars_end(&con, p);

            break;
        }

        /* ----------------------------------------------------- */

        case IN_RELOG:
            send_relog_response(&con);
            break;

        /* ----------------------------------------------------- */

        case IN_CHARLIST_REQUEST:
        {
            u8 worldid = p_decode1(&p);
            u8 channelid = p_decode1(&p);

            if (worldid != client->world)
            {
                prln("Dropping client for trying to "
                     "select another world's chan");
                goto cleanup;
            }

            client->channel = channelid;
            *dst_world = worlds[worldid];

            character_data chars[MAX_CHAR_SLOTS];
            u16 nchars =
                chars_by_world(
                    client->account_id,
                    client->world,
                    chars
                );

            u8* p = world_chars_begin(nchars);

            for (u16 i = 0; i < nchars; ++i) {
                char_encode(&p, &chars[i]);
            }

            world_chars_end(
                &con,
                p,
                char_slots(client->account_id)
            );
            break;
        }

        /* ----------------------------------------------------- */

        case IN_CHAR_SELECT:
        {
            client->char_id = p_decode4(&p);

            u8 ip[4] = { 127, 0, 0, 1 };
            send_connect_ip(
                &con,
                ip,
                worlds[client->world]
                    .channels[client->channel].port,
                client->char_id
            );
            break;
        }

        /* ----------------------------------------------------- */

        case IN_CHECK_CHAR_NAME:
            p_decode_str(&p, fmtbuf);
            send_char_name_response(&con, fmtbuf, 1);
            /* TODO: char creation */
            break;

        /* ----------------------------------------------------- */

        }
    }

cleanup:
    maple_close(&con);

    return retcode;
}

/* ------------------------------------------------------------- */

internal
int channel_server(
    int sockfd,
    client_data* client,
    world_data* world)
{
    b32 bot_spawned = 0;

    character_data bot = hardcoded_chars[0];
    bot.id = client->char_id + 0x7fffffff;
    bot.face = 20000;
    bot.hair = 30000;
    memeset(bot.cover_equips, 0, sizeof(bot.cover_equips));
    strcpy(bot.name, "Slave");

    /* --- */

    int retcode = 0;

    connection con = {0};
    if (maple_accept(sockfd, &con) < 0)
    {
        retcode = 1;
        goto cleanup;
    }

    /* TODO: character pool */
    character_data ch;
    if (char_by_id(client->char_id, &ch) < 0)
    {
        prln("Invalid character id after server transfer");
        goto cleanup;
    }

    while (1)
    {
        intptr nread = maple_recv(&con, packet_buf);
        retcode = nread < 0;
        if (nread <= 0) {
            goto cleanup;
        }

        u8* p = packet_buf;
        u16 hdr = p_decode2(&p);

        if (!client->in_game)
        {
            if (hdr != IN_PLAYER_LOAD) {
                /* refuse every packet until the
                   character is loaded */
                continue;
            }

            u32 char_id = p_decode4(&p);
            if (char_id != client->char_id)
            {
                prln("Dropped client that was trying "
                     "to perform remote hack");
                goto cleanup;
            }

            char_send_connect_data(&con, &ch, client->channel);

            char* header = world->header;
            if (strlen(header)) {
                send_scrolling_header(&con, header);
            }

            client->in_game = 1;

            continue;
        }

        switch (hdr)
        {
            case IN_PLAYER_MOVE:
            {
                /*u8 portal_count = */p_decode1(&p);
                p_decode4(&p);

                movement_data m[MAX_MOVEMENT_DATA];
                u8 nmovements = movement_decode(&p, m);

                movement_apply(m, nmovements, &ch);
                movement_apply(m, nmovements, &bot);

                if (!bot_spawned) {
                    char_send_spawn(&con, &bot);
                    bot_spawned = 1;
                }

                movement_send(&con, m, nmovements, bot.id);
                break;
            }

            /* ------------------------------------------------- */

            case IN_PLAYER_INFO:
            {
                /* when a character is double clicked */

                p_decode4(&p); /* tick count */
                u32 id = p_decode4(&p);

                /* TODO: character pool */
                if (id == bot.id) {
                    char_send_info(&con, &bot, 0);
                }
                else if (id == client->char_id) {
                    char_send_info(&con, &ch, 1);
                }
                else {
                    prln("Unknown char info requested");
                }
                break;
            }
        }
    }

cleanup:
    maple_close(&con);

    return retcode;
}

/* ------------------------------------------------------------- */

internal
int junoms(int argc, char const* argv[])
{
    prln("JunoMS pre-alpha v0.0.18");

    client_data client;
    world_data dst_world;
    /* this would normally be obtained through interserv */

    init_hardcoded_worlds();
    init_hardcoded_chars();

    while (1)
    {
        prln("# Login Server");

        int sockfd = tcp_socket(8484);
        if (sockfd < 0) {
            return 1;
        }

        while (!client.account_id ||
               !client.char_id ||
               !client.logged_in)
        {
            memeset(&client, 0, sizeof(client));

            if (login_server(sockfd, &client, &dst_world)) {
                return 1;
            }
        }

        close(sockfd);

        /* --- */

        prln("# Channel Server");

        sockfd = tcp_socket(
            dst_world.channels[client.channel].port
        );

        if (sockfd < 0) {
            return 1;
        }

        if (channel_server(sockfd, &client, &dst_world)) {
            return 1;
        }

        close(sockfd);
    }

    return 0;
}

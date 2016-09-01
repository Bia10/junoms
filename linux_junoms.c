#include "syscalls.h"

typedef unsigned long long	u64;
typedef unsigned int		u32;
typedef unsigned short		u16;
typedef unsigned char		u8;

typedef long long	i64;
typedef int			i32;
typedef short		i16;
typedef char		i8;

typedef i32	b32;

// TODO: find reliable ways to ensure that these types are the size I expect 

#define global_var static
#define array_count(a) (sizeof(a) / sizeof((a)[0]))
#define abs(v) ((v) < 0 ? -(v) : (v))

// ---

#define stdout 1
#define stderr 2

i64
write(int fd, void* data, i64 nbytes)
{
	return (i64)
		syscall3(
			SYS_write, 
			(void*)(i64)fd,
			(void*)data, 
			(void*)nbytes
		);
}

i64
read(int fd, void* data, i64 nbytes)
{
	return (i64)
		syscall3(
			SYS_read, 
			(void*)(i64)fd,
			(void*)data, 
			(void*)nbytes
		);
}

void
close(int fd) {
	syscall1(SYS_close, (void*)(i64)fd);
}

i64 
strlen(char* str)
{
	char* p;
	for(p = str; *p; ++p);
	return p - str;
}

i64
fprln(int fd, char* str) {
	return write(fd, str, strlen(str)) + write(fd, "\n", 1);
}

i64
fputs(int fd, char* str) {
	return write(fd, str, strlen(str));
}

i64 
puts(char* str) {
	return fputs(stdout, str);
}

i64 
prln(char* str) {
	return fprln(stdout, str);
}

void
die(char* msg)
{
	write(stderr, "ORERU: ", 7);
	fprln(stderr, msg);
}

// ---

#define af_inet	2

#define sock_stream 1

int 
socket(u16 family, i32 type, i32 protocol)
{
	return (int)(i64)
		syscall3(
			SYS_socket, 
			(void*)(i64)family,
			(void*)(i64)type, 
			(void*)(i64)protocol
		);
}

typedef struct 
{
	u16	family;
	u16	port; // NOTE: this is big endian!!!!!!! use letobe16u
	u32	addr;
	u8	zero[8];
}
sockaddr_in;

u16 
letobe16u(u16 v) {
	return (v << 8) | (v >> 8); 
}

int 
bind(int sockfd, sockaddr_in* addr)
{
	return (int)(i64)
		syscall3(
			SYS_bind, 
			(void*)(i64)sockfd, 
			addr, 
			(void*)sizeof(sockaddr_in)
		);
}

int
listen(int sockfd, i64 backlog)
{
	return (int)(i64)
		syscall2(
			SYS_listen, 
			(void*)(i64)sockfd, 
			(void*)backlog
		);
}

int
accept(int sockfd, sockaddr_in* addr)
{
	i64 addrlen = sizeof(sockaddr_in);
	return (int)(i64)
		syscall3(
			SYS_accept, 
			(void*)(i64)sockfd, 
			addr, 
			&addrlen
		);
}

#define ipproto_tcp 6

#define tcp_nodelay 1

int
setsockopt(int sockfd, i32 level, i32 optname, void* optval, u32 optlen)
{
	return (int)(i64)
		syscall5(
			SYS_setsockopt, 
			(void*)(i64)sockfd,
			(void*)(i64)level, 
			(void*)(i64)optname, 
			optval, 
			(void*)(i64)optlen
		);
}

// forces a flush of the pending packets on the next send
int
tcp_force_flush(int sockfd, b32 enabled) {
#if JMS_TCP_NODELAY
	return setsockopt(sockfd, ipproto_tcp, tcp_nodelay, &enabled, sizeof(b32));
#else
	return 0;
#endif
}

// ---

i64
getrandom(void* buf, i64 nbytes, u32 flags)
{
	return (i64)
		syscall3(
			SYS_getrandom, 
			buf, 
			(void*)nbytes, 
			(void*)(i64)flags
		);
}

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

u8 ror(u8 v, u8 n) // 1kpp hype
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

// 100-ns intervals between jan 1 1601 and jan 1 1970
#define epoch_diff 116444736000000000LL

inline u64
unix_msec_to_filetime(u64 unix_mseconds) {
	return epoch_diff + unix_mseconds * 10000LL;
}

inline u64
unix_to_filetime(u64 unix_seconds) {
	return unix_msec_to_filetime(unix_seconds * 1000LL);
}

inline u64
filetime_to_unix_msec(u64 filetime) {
	return (filetime - epoch_diff) / 10000LL;
}

inline u64
filetime_to_unix(u64 filetime) {
	return filetime_to_unix_msec(filetime) / 1000LL;
}

#define clock_realtime 0

typedef struct
{
	i64 sec;
	i64 nsec;
}
timespec;

int
clock_gettime(u32 clock_id, timespec* ts) {
	return (int)(i64)syscall2(SYS_clock_gettime, (void*)(i64)clock_id, ts);
}

u64
unix_now_msec()
{
	timespec ts = {0};
	clock_gettime(clock_realtime, &ts);
	return ts.sec * 1000 + ts.nsec / 1000000;
}

inline u64 unix_now() { return unix_now_msec() / 1000; }
inline u64 filetime_now() { return unix_msec_to_filetime(unix_now_msec()); }

// ---

char 
toupper(char c) {
	return (c >= 'a' && c <= 'z') ? c - 0x20 : c;
}

char 
tolower(char c) {
	return (c >= 'A' && c <= 'Z') ? c + 0x20 : c;
}

void
strdo(char* str, char (* func)(char c))
{
	for (; *str; ++str) {
		*str = func(*str);
	}
}

i64
uitoa(u8 base, u64 val, char* buf, i64 width, char filler) 
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

	i64 res = p - buf;
	*p-- = 0;

	char c;
	while (p > buf) 
	{
		// flip the string
		c = *p;
		*(p--) = *buf;
		*(buf++) = c;
	}

	return res;
}

i64
itoa(u8 base, i64 val, char* buf, i64 width, char filler) 
{
	if (val < 0) 
	{
		*(buf++) = '-';
		val = -val;
	}

	return uitoa(base, (u64)val, buf, width, filler);
}

int
atoui(char* str, u8 base, u64* res)
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
			// overflow
			return -1;
		}

		prev = *res;
	}

	return 0;
}

int
atoi(char* str, u8 base, i64* res)
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
		// overflow
		return -1;
	}

	*res = (i64)ures;

	if (negative) {
		*res = -*res;
	}

	return 0;
}

void
memcpy(void* dst, void* src, i64 nbytes)
{
	i64 i = 0;

	if (nbytes % sizeof(u64) == 0) 
	{
		u64* dst_chunks = (u64*)dst;
		u64* src_chunks = (u64*)src;

		for (; i < nbytes / sizeof(u64); ++i) {
			dst_chunks[i] = src_chunks[i];
		}
	}
	else 
	{
		u8* dst_bytes = (u8*)dst;
		u8* src_bytes = (u8*)src;

		for (; i < nbytes; ++i) {
			dst_bytes[i] = src_bytes[i];
		}
	}
}

void
memset(void* dst, u8 value, i64 nbytes)
{
	i64 i = 0;

	if (nbytes % sizeof(u64) == 0) 
	{
		u64* dst_chunks = (u64*)dst;
		u64 chunk = 
			(u64)value | (u64)(value << 8) | 
			(u64)(value << 16) | (u64)(value << 24);

		for (; i < nbytes / sizeof(u64); ++i) {
			dst_chunks[i] = chunk;
		}
	}
	else 
	{
		u8* dst_bytes = (u8*)dst;

		for (; i < nbytes; ++i) {
			dst_bytes[i] = value;
		}
	}
}

void
strcpy(char* dst, char* src) {
	memcpy((u8*)dst, (u8*)src, strlen(src) + 1);
}

b32
streq(char* a, char* b)
{
	for (; *a && *b; ++a, ++b)
	{
		if (*a != *b) {
			return 0;
		}
	}

	return *a == *b;
}

b32
strneq(char* a, char* b, i64 len)
{
	i64 i;

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

char* strstr(char* haystack, char* needle)
{
	i64 len = strlen(needle);

	for(; *haystack; ++haystack) 
	{
		if (strneq(haystack, needle, len)) {
			return haystack;
		}
	}

	return 0;
}

// ---

// all the aes stuff is heavily based on TitanMS
// TODO: learn more about AES and clean up this code

// https://en.wikipedia.org/wiki/Rijndael_key_schedule
global_var
u8 aes_rcon[256] = 
{
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 
	0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 
	0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 
	0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 
	0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 
	0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 
	0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 
	0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 
	0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 
	0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 
	0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 
	0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 
	0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 
	0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d
};

// https://en.wikipedia.org/wiki/Rijndael_S-box
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

void
aes_rotate(u8* word)
{
	u8 tmp = word[0];
	memcpy(word, word + 1, 3);
	word[3] = tmp;
}

void
aes_core(u8* word, u64 iter)
{
	aes_rotate(word);

	for (u8 i = 0; i < 4; ++i) {
		word[i] = aes_sbox[word[i]];
	}

	// xor the rcon operation with the first byte
	word[0] ^= aes_rcon[iter];
}

void
aes_expand_key(u8* key, u8* expanded_key, u8 size, u64 expanded_size)
{
	u64 current_size = 0;
	u64 rcon_iter = 1;

	u8 tmp[4];

	// first bytes are just the initial key
	memcpy(expanded_key, key, size);
	current_size += size;

	while (current_size < expanded_size)
	{
		// save previous 4 bytes to a tmp buffer
		memcpy(tmp, expanded_key + current_size - 4, 4);

		// apply the core schedule to tmp every keysize bytes and increment rcon
		// iteration
		if (current_size % size == 0) {
			aes_core(tmp, rcon_iter++);
		}

		// extra sbox for 256-bit keys
		if (size == 32 && current_size % size == 16) 
		{
			for (u8 i = 0; i < 4; ++i) {
				tmp[i] = aes_sbox[tmp[i]];
			}
		}

		// xor tmp with the 4-byte block keysize bytes before the new expanded 
		// key. these will be the next four bytes stored in tmp.
		// TODO: optimize this by xoring 4 bytes all at once, same for other 
		//       parts of this aes implementation
		for (u8 i = 0; i < 4; ++i) 
		{
			expanded_key[current_size] = 
				expanded_key[current_size - size] ^ tmp[i];

			++current_size;
		}
	}
}

void
aes_sub_bytes(u8* state)
{
	for (u8 i = 0; i < 16; ++i) {
		state[i] = aes_sbox[state[i]];
	}
}

void
aes_shift_row(u8* state, u8 n)
{
	u8 tmp;

	// basically rotates left by 8 bits
	for (u8 i = 0; i < n; ++i)
	{
		tmp = state[0];
		memcpy(state, state + 1, 3);
		state[3] = tmp;
	}
}

void
aes_shift_rows(u8* state)
{
	for (u8 i = 0; i < 4; ++i) {
		aes_shift_row(state + i * 4, i);
	}
}

void
aes_add_round_key(u8* state, u8* round_key)
{
	for (u8 i = 0; i < 16; ++i) {
		state[i] ^= round_key[i];
	}
}

u8
galois_multiplication(u8 a, u8 b)
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

void
aes_mix_column(u8* col)
{
	u8 cpy[4];
	memcpy(cpy, col, 4);

	col[0] = 	galois_multiplication(cpy[0], 2) ^
				galois_multiplication(cpy[3], 1) ^
				galois_multiplication(cpy[2], 1) ^
				galois_multiplication(cpy[1], 3);

	col[1] =	galois_multiplication(cpy[1], 2) ^
				galois_multiplication(cpy[0], 1) ^
				galois_multiplication(cpy[3], 1) ^
				galois_multiplication(cpy[2], 3);

	col[2] =	galois_multiplication(cpy[2], 2) ^
				galois_multiplication(cpy[1], 1) ^
				galois_multiplication(cpy[0], 1) ^
				galois_multiplication(cpy[3], 3);

	col[3] =	galois_multiplication(cpy[3], 2) ^
				galois_multiplication(cpy[2], 1) ^
				galois_multiplication(cpy[1], 1) ^
				galois_multiplication(cpy[0], 3);
}

void
aes_mix_columns(u8* state)
{
	u8 column[4];

	for (u8 i = 0; i < 4; ++i)
	{
		// extract a column as an array
		for (u8 j = 0; j < 4; ++j) {
			column[j] = state[j * 4 + i];
		}

		// mix it
		aes_mix_column(column);

		// put it back in the matrix
		for (u8 j = 0; j < 4; ++j) {
			state[j * 4 + i] = column[j];
		}
	}
}

void
aes_round(u8* state, u8* round_key)
{
	aes_sub_bytes(state);
	aes_shift_rows(state);
	aes_mix_columns(state);
	aes_add_round_key(state, round_key);
}

void 
aes_create_round_key(u8* expanded_key, u8* round_key)
{
	for (u8 i = 0; i < 4; ++i)
	{
		for (u8 j = 0; j < 4; ++j) {
			round_key[i + j * 4] = expanded_key[i * 4 + j];
		}
	}
}

void
aes_main(u8* state, u8* expanded_key, u64 nrounds)
{
	u8 round_key[16];

	aes_create_round_key(expanded_key, round_key);
	aes_add_round_key(state, round_key);

	for (u64 i = 1; i < nrounds; ++i)
	{
		aes_create_round_key(expanded_key + i * 16, round_key);
		aes_round(state, round_key);
	}

	aes_create_round_key(expanded_key + nrounds * 16, round_key);
	aes_sub_bytes(state);
	aes_shift_rows(state);
	aes_add_round_key(state, round_key);
}

void
aes_transform(u8* input, u8* output, u8* key, u8 key_size)
{
	u8 expanded_key[15 * 16];

	u64 nrounds;
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

	u64 expanded_key_size = 16 * (nrounds + 1);
	u8 block[16];

	// block is a column-major order 4x4 matrix, so we need to map our input to
	// it correctly
	for (u8 i = 0; i < 4; ++i)
	{
		for (u8 j = 0; j < 4; ++j) {
			block[i + j * 4] = input[i * 4 + j];
		}
	}

	aes_expand_key(key, expanded_key, key_size, expanded_key_size);
	aes_main(block, expanded_key, nrounds);

	// unmap the matrix after the transformation back into the output buffer
	for (u8 i = 0; i < 4; ++i)
	{
		for (u8 j = 0; j < 4; ++j) {
			output[i * 4 + j] = block[i + j * 4];
		}
	}
}

// ---

void
maple_aes_ofb_transform(u8* buf, u8* iv, i64 nbytes)
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

	// first iteration (initializes input)
	aes_transform(expanded_dong_i_mean_iv, output, aeskey, 32);

	for (u8 i = 0; i < 16; ++i) {
		plaintext[i] = output[i] ^ buf[i];
	}

	i64 chunks = nbytes / 16 + 1;

	if (chunks == 1) 
	{
		memcpy(buf, plaintext, nbytes);
		return;
	}

	memcpy(buf, plaintext, 16);
	memcpy(input, output, 16);

	// all chunks except the last one
	for (i64 i = 1; i < chunks - 1; ++i) 
	{
		aes_transform(input, output, aeskey, 32);

		i64 offset = i * 16;

		for (u8 j = 0; j < 16; ++j) {
			plaintext[j] = output[j] ^ buf[offset + j];
		}

		memcpy(buf + offset, plaintext, 16);
		memcpy(input, output, 16);
	}

	// last chunk
	aes_transform(input, output, aeskey, 32);

	i64 offset = (chunks - 1) * 16;

	for (u8 j = 0; j < 16; ++j) {
		plaintext[j] = output[j] ^ buf[offset + j];
	}

	memcpy(buf + offset, plaintext, nbytes % 16);
	memcpy(input, output, 16);
}

// lol idk some fucked up key routine used to shuffle the iv
void maple_shuffle_iv(u8* iv) {
	u8 shit[256] = 
	{
		0xec, 0x3f, 0x77, 0xa4, 0x45, 0xd0, 0x71, 0xbf, 0xb7, 0x98, 0x20, 0xfc,
		0x4b, 0xe9, 0xb3, 0xe1, 0x5c, 0x22, 0xf7, 0x0c,	0x44, 0x1b, 0x81, 0xbd, 
		0x63, 0x8d, 0xd4, 0xc3, 0xf2, 0x10, 0x19, 0xe0, 0xfb, 0xa1, 0x6e, 0x66,	
		0xea, 0xae, 0xd6, 0xce, 0x06, 0x18, 0x4e, 0xeb, 0x78, 0x95, 0xdb, 0xba, 
		0xb6, 0x42, 0x7a, 0x2a, 0x83, 0x0b, 0x54, 0x67, 0x6d, 0xe8, 0x65, 0xe7,
		0x2f, 0x07, 0xf3, 0xaa, 0x27, 0x7b, 0x85, 0xb0,	0x26, 0xfd, 0x8b, 0xa9, 
		0xfa, 0xbe, 0xa8, 0xd7, 0xcb, 0xcc, 0x92, 0xda, 0xf9, 0x93, 0x60, 0x2d,	
		0xdd, 0xd2, 0xa2, 0x9b, 0x39, 0x5f, 0x82, 0x21, 0x4c, 0x69, 0xf8, 0x31, 
		0x87, 0xee, 0x8e, 0xad, 0x8c, 0x6a, 0xbc, 0xb5, 0x6b, 0x59, 0x13, 0xf1,
		0x04, 0x00, 0xf6, 0x5a, 0x35, 0x79, 0x48, 0x8f,	0x15, 0xcd, 0x97, 0x57, 
		0x12, 0x3e, 0x37, 0xff, 0x9d, 0x4f, 0x51, 0xf5, 0xa3, 0x70, 0xbb, 0x14,	
		0x75, 0xc2, 0xb8, 0x72, 0xc0, 0xed, 0x7d, 0x68, 0xc9, 0x2e, 0x0d, 0x62, 
		0x46, 0x17, 0x11, 0x4d,	0x6c, 0xc4, 0x7e, 0x53, 0xc1, 0x25, 0xc7, 0x9a,
		0x1c, 0x88, 0x58, 0x2c, 0x89, 0xdc, 0x02, 0x64,	0x40, 0x01, 0x5d, 0x38, 
		0xa5, 0xe2, 0xaf, 0x55, 0xd5, 0xef, 0x1a, 0x7c, 0xa7, 0x5b, 0xa6, 0x6f,	
		0x86, 0x9f, 0x73, 0xe6, 0x0a, 0xde, 0x2b, 0x99, 0x4a, 0x47, 0x9c, 0xdf, 
		0x09, 0x76, 0x9e, 0x30,	0x0e, 0xe4, 0xb2, 0x94, 0xa0, 0x3b, 0x34, 0x1d,
		0x28, 0x0f, 0x36, 0xe3, 0x23, 0xb4, 0x03, 0xd8, 0x90, 0xc8, 0x3c, 0xfe,
		0x5e, 0x32, 0x24, 0x50, 0x1f, 0x3a, 0x43, 0x8a, 0x96, 0x41, 0x74, 0xac,
		0x52, 0x33, 0xf0, 0xd9, 0x29, 0x80, 0xb1, 0x16, 0xd3, 0xab, 0x91, 0xb9,
		0x84, 0x7f, 0x61, 0x1e,	0xcf, 0xc5, 0xd1, 0x56, 0x3d, 0xca, 0xf4, 0x05,
		0xc6, 0xe5, 0x08, 0x49
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

	memcpy(iv, new_iv, 4);
}

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

#define maple_version 62
#define maple_encrypted_hdr_size 4

u32
maple_encrypted_hdr(u8* iv, u16 nbytes)
{
	// the lowest 16 bits are the high part of the send IV, xored with 
	// ffff - mapleversion (or -(mapleversion + 1)).
	//
	// the highest 16 bits are the low part xored with the size of the packet
	// to obtain the packet size we simply hor the low part with the high part
	// again

	u16* high_iv = (u16*)(iv + 2);

	u16 lowpart = *high_iv;

	u16 version = maple_version;
	version = 0xFFFF - version;
	lowpart ^= version;

	u16 hipart = lowpart ^ nbytes;

	return (u32)lowpart | ((u32)hipart << 16);
}

// ---

// used to build packets everywhere
global_var
u8 packet_buf[0x10000];

void
p_encode2(u8** p, u16 v);

u8*
p_new(u16 hdr, u8* buf) {
	u8* res = buf;
	p_encode2(&res, hdr);
	return res;
}

void
p_encode1(u8** p, u8 v) {
	*(*p)++ = v;
}

void
p_append(u8** p, void* buf, u64 nbytes)
{
	memcpy(*p, buf, nbytes);
	*p += nbytes;
}

void
p_encode2(u8** p, u16 v) {
	p_append(p, &v, 2);
}

void
p_encode4(u8** p, u32 v) {
	p_append(p, &v, 4);
}

void
p_encode8(u8** p, u64 v) {
	p_append(p, &v, 8);
}

void
p_encode_buf(u8** p, u8* buf, u16 nbytes)
{
	p_encode2(p, nbytes);
	p_append(p, buf, nbytes);
}

void
p_encode_str(u8** p, char* str) {
	p_encode_buf(p, (u8*)str, strlen(str));
}

u8
p_decode1(u8** p) {
	return *(*p)++;
}

void
p_get_bytes(u8** p, void* dst, u64 nbytes)
{
	memcpy(dst, *p, nbytes);
	*p += nbytes;
}

u16
p_decode2(u8** p) {
	u16 res;
	p_get_bytes(p, &res, 2);
	return res;
}

u32
p_decode4(u8** p) {
	u32 res;
	p_get_bytes(p, &res, 4);
	return res;
}

u64
p_decode8(u8** p) {
	u64 res;
	p_get_bytes(p, &res, 8);
	return res;
}

u16
p_decode_buf(u8** p, u8* buf) {
	u16 len = p_decode2(p);
	p_get_bytes(p, buf, len);
	return len;
}

void
p_decode_str(u8** p, char* str) {
	u16 len = p_decode_buf(p, (u8*)str);
	str[len] = 0;
}

// ---

global_var
char fmtbuf[0x10000]; // used to format strings

void print_bytes(u8* buf, u64 nbytes)
{
	for (u32 i = 0; i < nbytes; ++i)
	{
		uitoa(16, (u64)buf[i], fmtbuf, 2, '0');
		strdo(fmtbuf, toupper);
		puts(fmtbuf);
		puts(" ");
	}
}

void print_bytes_pre(char* prefix, u8* buf, u64 nbytes)
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

// ---

int
tcp_socket(u16 port)
{
	int sockfd = socket(af_inet, sock_stream, ipproto_tcp);
	if (sockfd < 0) {
		die("Failed to create socket");
		return sockfd;
	}

	sockaddr_in serv_addr = {0};
	serv_addr.family = af_inet;
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

#define out_handshake	0x000D

int
maple_accept(int sockfd, connection* con)
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

	// build handshake packet
	u8* p = p_new(out_handshake, packet_buf);
	p_encode4(&p, maple_version); // maple version
	p_append(&p, con->iv_recv, 4); 
	p_append(&p, con->iv_send, 4); 
	p_encode1(&p, 8); // region

	tcp_force_flush(con->fd, 1);
	if (write(con->fd, packet_buf, p - packet_buf) < 0) {
		die("Failed to send handshake packet");
		return -1;
	}
	tcp_force_flush(con->fd, 0);

#if JMS_DEBUG_SEND
	puts("Sent handshake packet: ");
	print_bytes(packet_buf, p - packet_buf);
	puts("\n");
#endif

	return 0;
}

void
maple_close(connection* con)
{
	close(con->fd);
}

i64
read_all(int fd, void* dst, u64 nbytes)
{
	u64 nread = 0;

	while (nread < nbytes)
	{
		i64 cb = read(fd, dst, nbytes);
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

// NOTE: packets can be up to 0xFFFF bytes large, so make sure dst has enough
//       room.
i64
maple_read(connection* con, u8* dst)
{
	i64 nread;
	u32 encrypted_hdr;

	// encrypted header
	nread = read_all(con->fd, &encrypted_hdr, maple_encrypted_hdr_size);
	if (nread <= 0) {
		return nread;
	}

	// decode packet length from header
	u32 packet_len = 
		(encrypted_hdr & 0x0000FFFF) ^ 
		(encrypted_hdr >> 16);

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
	puts("\n<- Encrypted header ");

	uitoa(16, encrypted_hdr, fmtbuf, 8, '0');
	puts(fmtbuf);

	puts(", packet length: ");

	uitoa(10, (u64)packet_len, fmtbuf, 0, 0);
	prln(fmtbuf);
#endif

	// packet body
	nread = read_all(con->fd, dst, packet_len);
	if (nread <= 0) {
		return nread;
	}

	dbg_recv_print_encrypted_packet("<- Encrypted", dst, packet_len);

	maple_aes_ofb_transform(dst, con->iv_recv, packet_len);
	dbg_recv_print_encrypted_packet("<- AES Decrypted", dst, packet_len);

	maple_decrypt(dst, packet_len);
	dbg_recv_print_packet("<-", dst, packet_len);

	maple_shuffle_iv(con->iv_recv);

	return nread;
}

// NOTE: this is ENCRYPTED send. to send unencrypted data, just use write.
i64
maple_write(connection* con, u8* packet, u16 nbytes)
{
	u32 encrypted_hdr = maple_encrypted_hdr(con->iv_send, nbytes);

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
	puts("\n-> Encrypted header ");

	uitoa(16, encrypted_hdr, fmtbuf, 8, '0');
	prln(fmtbuf);
#endif

	if (write(con->fd, &encrypted_hdr, maple_encrypted_hdr_size) != 
			maple_encrypted_hdr_size) 
	{
		prln("W: failed to write encrypted header");
		return -1;
	}
	
	dbg_send_print_packet("->", packet, nbytes);

	maple_encrypt(packet, nbytes);
	dbg_send_print_encrypted_packet("-> Maple Encrypted:", packet, nbytes);

	u64 pos = 0, first = 1;
	while (nbytes > pos) {
		// TODO: clean the first flag up
		if (nbytes > pos + 1460 - first * 4) {
			maple_aes_ofb_transform(packet, con->iv_send, 1460 - first * 4);
		} else {
			maple_aes_ofb_transform(packet, con->iv_send, nbytes - pos);
		}

		pos += 1460 - first * 4;

		if (first) {
			first = 0;
		}
	}

	dbg_send_print_encrypted_packet("-> Encrypted:", packet, nbytes);

	maple_shuffle_iv(con->iv_send);

	tcp_force_flush(con->fd, 1);
	i64 res = write(con->fd, packet, nbytes);
	tcp_force_flush(con->fd, 0);

	return res;
}

// ---

// common
#define out_ping 0x0011

#define in_pong	0x0018

// login server
#define in_login_password			0x0001
#define in_after_login				0x0009
#define in_server_list_request		0x000B
#define in_server_list_rerequest	0x0004
#define in_server_status_request	0x0006
#define in_view_all_char			0x000D
#define in_relog					0x001C
#define in_charlist_request			0x0005
#define in_char_select				0x0013
#define in_check_char_name			0x0015
#define in_delete_char				0x0017
#define in_set_gender				0x0008
#define in_register_pin				0x000A
#define in_guest_login				0x0002

#define out_login_status			0x0000
#define out_server_status			0x0003
#define out_pin_operation			0x0006
#define out_all_char_list			0x0008
#define out_server_list				0x000A
#define out_char_list				0x000B
#define out_server_ip				0x000C
#define out_char_name_response		0x000D
#define out_add_new_char_entry		0x000E
#define out_delete_char_response	0x000F
#define out_relog_response			0x0016
#define out_gender_done				0x0004
#define out_pin_assigned			0x0007

// channel server
#define in_player_load			0x0014
#define in_player_update		0x00C0
#define in_player_move			0x0026
#define in_player_info			0x0059

#define out_server_message		0x0041
#define out_channel_change		0x0010
#define out_stats_update		0x001C
#define out_map_change			0x005C
#define out_player_info			0x003A
#define out_player_movement		0x008D
#define out_player_spawn		0x0078

void
ping(connection* con)
{
	u8* p = p_new(out_ping, packet_buf);
	maple_write(con, packet_buf, p - packet_buf);
}

void
auth_success_request_pin(connection* con, char* user)
{
	u8 tacos[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0xFF, 0x6A, 0x01, 0x00, 
		0x00, // player status (set gender, set pin)
		0x00, // admin ? disables trading and enables gm commands if true
		0x4E, // gm related flag, not sure
	};

	// ???
	u8 pizza[] = {
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDC, 
		0x3D, 0x0B, 0x28, 0x64, 0xC5, 0x01, 0x08, 0x00, 0x00, 0x00, 
	};

	u8* p = p_new(out_login_status, packet_buf);
	p_append(&p, tacos, sizeof(tacos));
	p_encode_str(&p, user);
	p_append(&p, pizza, sizeof(pizza));

	maple_write(con, packet_buf, p - packet_buf);
}

#define login_id_deleted			3
#define login_incorrect_password	4
#define login_not_registered		5
#define login_sys_err_1				6
#define login_already_logged		7
#define login_sys_err_2				8
#define login_sys_err_3				9
#define login_too_many_1			10
#define login_not_20				11
#define login_gm_wrong_ip			13
#define login_wrong_gateway_1		14
#define login_too_many_2			15
#define login_unverified_1			16
#define login_wrong_gateway_2		17
#define login_unverified_2			21
#define login_license				23
#define login_ems_notice			25
#define login_trial					27

void
login_failed(connection* con, u32 reason)
{
	u8* p = p_new(out_login_status, packet_buf);
	p_encode4(&p, reason);
	p_encode2(&p, 0);

	maple_write(con, packet_buf, p - packet_buf);
}

#define ban_deleted				0
#define ban_hacking				1
#define ban_macro				2
#define ban_ad					3
#define ban_harassment			4
#define ban_profane				5
#define ban_scam				6
#define ban_misconduct			7
#define ban_illegal_transaction	8
#define ban_illegal_charging	9
#define ban_temporary			10
#define ban_impersonating_gm	11
#define ban_illegal_programs	12
#define ban_megaphone			13
#define ban_null				14

void
login_banned(connection* con, u8 reason, u64 expire_filetime)
{
	u8 memes[5] = {0};

	u8* p = p_new(out_login_status, packet_buf);
	p_encode1(&p, 2);
	p_append(&p, memes, 5);
	p_encode1(&p, reason);
	p_encode8(&p, expire_filetime);

	maple_write(con, packet_buf, p - packet_buf);
}

#define pin_accepted	0
#define pin_new			1
#define pin_invalid		2
#define pin_sys_err		3
#define pin_enter		4

void
pin_operation(connection* con, u8 op)
{
	u8* p = p_new(out_pin_operation, packet_buf);
	p_encode1(&p, op);

	maple_write(con, packet_buf, p - packet_buf);
}

#define ribbon_no	0
#define ribbon_e	1
#define ribbon_n	2
#define ribbon_h	3

u8*
world_entry_begin(
	u8 id, 
	char* name, 
	u8 ribbon, 
	char* event_msg, 
	u16 exp_percent, 
	u16 drop_percent, 
	u8 max_channels)
{
	u8* p = p_new(out_server_list, packet_buf);
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

void
world_entry_append_channel(u8** p, u8 worldid, u8 id, char* name, u32 pop)
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

void
world_entry_end(connection* con, u8* p, u16 nbubbles, world_bubble* bubbles)
{
	p_encode2(&p, nbubbles);

	for (u16 i = 0; i < nbubbles; ++i)
	{
		p_encode2(&p, bubbles[i].x);
		p_encode2(&p, bubbles[i].y);
		p_encode_str(&p, bubbles[i].msg);
	}

	maple_write(con, packet_buf, p - packet_buf);
}

void
world_list_end(connection* con)
{
	u8* p = p_new(out_server_list, packet_buf);
	p_encode1(&p, 0xFF);
	maple_write(con, packet_buf, p - packet_buf);
}

#define server_normal	0
#define server_high		1
#define server_full		2

void
server_status(connection* con, u16 status)
{
	u8* p = p_new(out_server_status, packet_buf);
	p_encode2(&p, status);
	maple_write(con, packet_buf, p - packet_buf);
}

void
all_chars_count(connection* con, u32 nworlds, u32 last_visible_char_slot)
{
	u8* p = p_new(out_all_char_list, packet_buf);
	p_encode1(&p, 1);
	p_encode4(&p, nworlds);
	p_encode4(&p, last_visible_char_slot);
	maple_write(con, packet_buf, p - packet_buf);
}

u8* 
all_chars_begin(u8 worldid, u8 nchars)
{
	u8* p = p_new(out_all_char_list, packet_buf);
	p_encode1(&p, 0);
	p_encode1(&p, worldid);
	p_encode1(&p, nchars);

	return p;
}

// ---

#define invalid_id			((u32)-1)
#define invalid_map			999999999
#define item_no_expiration 	3439756800LL

#define max_ign_len			12
#define max_char_slots		36
#define max_worlds			15
#define max_channels		20
#define min_inv_slots		24
#define max_inv_slots		100
#define min_storage_slots	4
#define max_storage_slots	100
#define max_pets			3
#define max_vip_rock_maps	10
#define max_rock_maps		5

#define equipped_slots 51
#define buff_bitmask_bytes 16

#define equip_helm					1
#define equip_face					2
#define equip_eye					3
#define equip_earring				4
#define equip_top					5
#define equip_bottom				6
#define equip_shoe					7
#define equip_glove					8
#define equip_cape					9
#define equip_shield				10
#define equip_weapon				11
#define equip_ring1					12
#define equip_ring2					13
#define equip_pet_1					14
#define equip_ring3					15
#define equip_ring4					16
#define equip_pendant				17
#define equip_mount					18
#define equip_saddle				19
#define equip_pet_collar			20
#define equip_pet_label_ring_1		21
#define equip_pet_item_pouch_1		22
#define equip_pet_meso_magnet_1		23
#define equip_pet_auto_hp			24
#define equip_pet_auto_mp			25
#define equip_pet_wing_boots_1		26
#define equip_pet_binoculars_1		27
#define equip_pet_magic_scales_1	28
#define equip_pet_quote_ring_1		29
#define equip_pet_2					30
#define equip_pet_label_ring_2		31
#define equip_pet_quote_ring_2		32
#define equip_pet_item_pouch_2		33
#define equip_pet_meso_magnet_2		34
#define equip_pet_wing_boots_2		35
#define equip_pet_binoculars_2		36
#define equip_pet_magic_scales_2	37
#define equip_pet_equip_3			38
#define equip_pet_label_ring_3		39
#define equip_pet_quote_ring_3		40
#define equip_pet_item_pouch_3		41
#define equip_pet_meso_magnet_3		42
#define equip_pet_wing_boots_3		43
#define equip_pet_binoculars_3		44
#define equip_pet_magic_scales_3	45
#define equip_pet_item_ignore_1		46
#define equip_pet_item_ignore_2		47
#define equip_pet_item_ignore_3		48
#define equip_medal					49
#define equip_belt					50

#define ninventories	5
#define inv_equip		1
#define inv_use			2
#define inv_setup		3
#define inv_etc			4
#define inv_cash		5

// item_category
#define item_armor_helm			100
#define item_armor_face			101
#define item_armor_eye			102
#define item_armor_earring		103
#define item_armor_top			104
#define item_armor_overall		105
#define item_armor_bottom		106
#define item_armor_shoe			107
#define item_armor_glove		108
#define item_armor_shield		109
#define item_armor_cape			110
#define item_armor_ring			111
#define item_armor_pendant		112
#define item_medal				114
#define item_weapon_1h_sword	130
#define item_weapon_1h_axe		131
#define item_weapon_1h_mace		132
#define item_weapon_dagger		133
#define item_weapon_wand		137
#define item_weapon_staff		138
#define item_weapon_2h_sword	140
#define item_weapon_2h_axe		141
#define item_weapon_2h_mace		142
#define item_weapon_spear		143
#define item_weapon_polearm		144
#define item_weapon_bow			145
#define item_weapon_xbow		146
#define item_weapon_claw		147
#define item_weapon_knuckle		148
#define item_weapon_gun			149
#define item_mount				190
#define item_arrow				206
#define item_star				207
#define item_bullet				233

// item_data.type
#define item_equip	1
#define item_item	2
#define item_pet	3

// equip_stats.flags and item_stats.flags
#define item_lock			0x0001
#define item_spikes			0x0002
#define item_cold_protect	0x0004
#define item_untradeable	0x0008

typedef struct
{
	char owner[max_ign_len + 1]; // owner string
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
equip_stats;

typedef struct
{
	char maker[max_ign_len + 1]; // specially made by <ign>
	u16 amount;
	u16 flags;
}
item_stats;

typedef struct
{
	u64 id; // database id of the pet
	char name[max_ign_len + 1];
	u8 level;
	u16 closeness;
	u8 fullness;
}
pet_stats;

// TODO: separate specialized values for pets, equips etc into other structs?
typedef struct
{
	u32 id; 
	u8 type; // equip, item or pet
	u64 expire_time; // in unix seconds

	// access the correct union member according to type unless you want
	// the server to commit suicide by memory corruption
	union 
	{
		equip_stats	as_equip;
		item_stats	as_item;
		pet_stats	as_pet;
	};
}
item_data;

inline u32 item_category(u32 id) { return id / 10000; }
inline b32 item_is_rechargeable(u32 id) { 
	return item_category(id) == item_bullet || item_category(id) == item_star; 
}

void
pet_data_encode(u8** p, item_data* item)
{
	pet_stats* pet = &item->as_pet;

	p_encode1(p, item->type);
	p_encode4(p, item->id);
	p_encode1(p, 1); // cash item = true
	p_encode8(p, pet->id); // cash id
	p_encode8(p, 0); // pretty sure this is a timestamp
	p_append(p, pet->name, sizeof(pet->name));
	p_encode1(p, pet->level);
	p_encode2(p, pet->closeness);
	p_encode1(p, pet->fullness);
	p_encode8(p, unix_to_filetime(item->expire_time));
	p_encode4(p, 0);
	p_encode4(p, 0); // trial pet expire time?
}

void
item_data_encode(u8** p, item_data* item, i16 slot)
{
	if (slot) 
	{
		// equipped items have negative slot
		slot = abs(slot);

		if (slot > 100) {
			slot -= 100;
		}

		p_encode1(p, (u8)(i8)slot);
	}

	if (item->type == item_pet) {
		return pet_data_encode(p, item);
	}
	
	p_encode1(p, item->type);
	p_encode4(p, item->id);
	p_encode1(p, 0); // not a cash item
	p_encode8(p, unix_to_filetime(item->expire_time));

	if (item->type == item_equip)
	{
		// equip
		equip_stats* equip = &item->as_equip;

		p_encode1(p, equip->upgrade_slots);
		p_encode1(p, equip->level);
		p_encode2(p, equip->str);
		p_encode2(p, equip->dex);
		p_encode2(p, equip->intt);
		p_encode2(p, equip->luk);
		p_encode2(p, equip->hp);
		p_encode2(p, equip->mp);
		p_encode2(p, equip->watk);
		p_encode2(p, equip->matk);
		p_encode2(p, equip->wdef);
		p_encode2(p, equip->mdef);
		p_encode2(p, equip->acc);
		p_encode2(p, equip->avoid);
		p_encode2(p, equip->hands);
		p_encode2(p, equip->speed);
		p_encode2(p, equip->jump);
		p_encode_str(p, equip->owner);
		p_encode2(p, equip->flags);
		p_encode8(p, 0); // not sure what this is

		return;
	}

	// regular item
	item_stats* reg_item = &item->as_item;

	p_encode2(p, reg_item->amount);
	p_append(p, reg_item->maker, sizeof(reg_item->maker));
	p_encode2(p, reg_item->flags);

	if (item_is_rechargeable(item->id)) {
		p_encode8(p, 0); // idk, could be some kind of id
	}
}

// ---

#define sex_otokonoko	0
#define sex_onnanoko	1 // fucking weeb

typedef struct
{
	u32 id;
	char name[max_ign_len + 1];
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

	// slots -1 to -51 translated to 0-50
	item_data equips[equipped_slots];

	// slots -101 to -151 translated to 0-50
	item_data cover_equips[equipped_slots];

	// inv number starts at zero, so subtract 1 from inv_equip, inv_use etc
	u8 inv_capacity[ninventories];
	item_data inventory[ninventories][max_inv_slots]; // slots start at zero

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

void
char_data_encode_stats(u8** p, character_data* c)
{
	p_encode4(p, c->id);
	p_append(p, c->name, sizeof(c->name));
	p_encode1(p, c->gender);
	p_encode1(p, c->skin);
	p_encode4(p, c->face);
	p_encode4(p, c->hair);

	// TODO: summoned pet id's here
	// (I suppose the client will then send a request to summon given pet id's?)
	for (u8 i = 0; i < max_pets; ++i) {
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
	p_encode4(p, 0); // marriage flag
	p_encode4(p, c->map);
	p_encode1(p, c->spawn);
	p_encode4(p, 0);
}

void
char_data_encode_look(u8**p, character_data* c)
{
	p_encode1(p, c->gender);
	p_encode1(p, c->skin);
	p_encode4(p, c->face);
	p_encode1(p, 0); // TODO: check this
	p_encode4(p, c->hair);

	// normal equip slots that are not covered by other items
	b32 visible_slots[equipped_slots] = {0};

	// visible equips (cash and stuff that covers normal equips)
	for (u8 i = 0; i < equipped_slots; ++i)
	{
		if (!c->cover_equips[i].type && !c->equips[i].type) {
			continue;
		}

		p_encode1(p, i);
		
		if (i == equip_weapon && c->equips[i].type) {
			// we want the non-cash weapon id here because cash weapon id is 
			// added later on in the packet
			p_encode4(p, c->equips[i].id);
		} 
		else 
		{
			if (c->cover_equips[i].type) {
				// display the cover item
				p_encode4(p, c->cover_equips[i].id);
			}
			else {
				// no cover item, so make the base equip visible
				p_encode4(p, c->equips[i].id);
				visible_slots[i] = 1;
			}
		}
	}

	p_encode1(p, 0xFF); // list terminator?

	// covered equips (normal equips that have covering items over them)
	for (u8 i = 0; i < equipped_slots; ++i)
	{
		if (!c->equips[i].type) {
			continue;	
		}
		
		if (i == equip_weapon) {
			// cash weapon is after this item list
			continue;
		}

		if (visible_slots[i]) {
			continue;
		}

		p_encode1(p, i);
		p_encode4(p, c->equips[i].id);
	}

	p_encode1(p, 0xFF); // list terminator?
	p_encode4(p, c->cover_equips[equip_weapon].id); // cash weapon

	for (u8 i = 0; i < max_pets; ++i) {
		p_encode4(p, 0); // TODO: encode pet ITEM id's
	}
}

void
char_data_encode(u8** p, character_data* c)
{
	char_data_encode_stats(p, c);
	char_data_encode_look(p, c);

	// rankings
	p_encode1(p, 1); // enabled / disabled
	p_encode4(p, c->world_rank);
	p_encode4(p, (u32)c->world_rank_move);
	p_encode4(p, c->job_rank);
	p_encode4(p, (u32)c->job_rank_move);
}

void
all_chars_end(connection* con, u8* p) {
	maple_write(con, packet_buf, p - packet_buf);
}

void
relog_response(connection* con) 
{
	u8* p = p_new(out_relog_response, packet_buf);
	p_encode1(&p, 1);
	maple_write(con, packet_buf, p - packet_buf);
}

u8*
world_chars_begin(u8 nchars)
{
	u8* p = p_new(out_char_list, packet_buf);
	p_encode1(&p, 0);
	p_encode1(&p, nchars);
	
	return p;
}

void
world_chars_end(connection* con, u8* p, u32 nmaxchars)
{
	p_encode4(&p, nmaxchars);
	maple_write(con, packet_buf, p - packet_buf);
}

void
char_name_response(connection* con, char* name, b32 used)
{
	u8* p = p_new(out_char_name_response, packet_buf);
	p_encode_str(&p, name);
	p_encode1(&p, used ? 1 : 0);

	maple_write(con, packet_buf, p - packet_buf);
}

void
connect_ip(connection* con, u8* ip, u16 port, u32 char_id)
{
	u8 meme[5] = {0};

	u8* p = p_new(out_server_ip, packet_buf);
	p_encode2(&p, 0);
	p_append(&p, ip, 4);
	p_encode2(&p, port);
	p_encode4(&p, char_id);
	p_append(&p, meme, sizeof(meme));
	
	maple_write(con, packet_buf, p - packet_buf);
}

void
connect_data(connection* con, u8 channel_id, character_data* c)
{
	u8* p = p_new(out_map_change, packet_buf);
	p_encode4(&p, (u32)channel_id); // why 4 bytes?
	p_encode1(&p, 1); // portal counter (the one used in map rushers)
	p_encode1(&p, 1); // flag that indicates that it's a connect packet

#if 0
	// some multiline message that disappears in like 3 seconds
	// disabled because it's useless and it looks bad

	p_encode2(&p, 2); // line count
	p_encode_str(&p, "Hello"); // title
	p_encode_str(&p, "I have no idea what this ui is");
	p_encode_str(&p, "but it disappears pretty fast");
#else
	p_encode2(&p, 0);
#endif

	u8 rngseed[12];
	if (getrandom(&rngseed, sizeof(rngseed), 0) != sizeof(rngseed)) {
		prln("W: getrandom failed for rng seed");
	}
	p_append(&p, rngseed, sizeof(rngseed)); // 3 u32 seeds

	p_encode8(&p, (u64)-1);
	char_data_encode_stats(&p, c);
	p_encode1(&p, c->buddy_list_size);

	p_encode4(&p, c->meso);
	
	// max slots for each inventory
	for (u8 i = 1; i <= ninventories; ++i) {
		p_encode1(&p, c->inv_capacity[i - 1]);
	}

	// equipped items
	for (u8 i = equipped_slots - 1; i > 0; --i) 
	{
		item_data* item = &c->equips[i];
		if (!item->type) {
			continue;
		}

		// -50 to -1 (normal equips)
		item_data_encode(&p, item, -(i16)i);
	}

	p_encode1(&p, 0);

	for (u8 i = equipped_slots - 1; i > 0; --i) 
	{
		item_data* item = &c->cover_equips[i];
		if (!item->type) {
			continue;
		}

		// -150 to -101 (cash / cover items)
		item_data_encode(&p, item, -(i16)i - 100);
	}

	p_encode1(&p, 0);

	// items
	for (u8 inv = 0; inv < ninventories; ++inv) 
	{
		for (i16 i = 0; i < c->inv_capacity[inv]; ++i) 
		{
			item_data* item = &c->inventory[inv][i];
			if (!item->type) {
				continue;
			}

			item_data_encode(&p, item, i + 1);
			// slots in packets are 1-based, FUCK
		}

		p_encode1(&p, 0); // list terminator (zero slot)
	}

	p_encode2(&p, 0); // TODO: skills
	p_encode2(&p, 0);

	p_encode2(&p, 0); // TODO: quest info
	p_encode2(&p, 0);

	p_encode2(&p, 0); // minigame record list?
	p_encode2(&p, 0); // crush ring record list?
	p_encode2(&p, 0); // friendship ring record list?
	p_encode2(&p, 0); // marriage ring record list?

	// teleport rock locations TODO
	for (u8 i = 0; i < max_rock_maps; ++i) {
		p_encode4(&p, invalid_map);
	}

	// vip teleport rock locations TODO
	for (u8 i = 0; i < max_vip_rock_maps; ++i) {
		p_encode4(&p, invalid_map);
	}

	p_encode4(&p, 0);
	p_encode8(&p, filetime_now());

	maple_write(con, packet_buf, p - packet_buf);
}

void
player_info(connection* con, character_data* c, b32 is_self)
{
	u8* p = p_new(out_player_info, packet_buf);
	p_encode4(&p, c->id);
	p_encode1(&p, c->level);
	p_encode2(&p, c->job);
	p_encode2(&p, c->fame);
	p_encode1(&p, 0); // married flag
	p_encode_str(&p, "-"); // guild
	p_encode_str(&p, ""); // guild alliance
	p_encode1(&p, is_self ? 1 : 0);

	// TODO: pets info
	p_encode1(&p, 0);

	p_encode1(&p, 0); // has mount ?
	// TODO: mount info
	
	p_encode1(&p, 0); // wishlist size
	// TODO: wishlist info
	
	// TODO: monster book
	// TODO: check if v62 has monster book (prob not)
	p_encode4(&p, 0);
	p_encode4(&p, 0);
	p_encode4(&p, 0);
	p_encode4(&p, 0);
	p_encode4(&p, 0);

	maple_write(con, packet_buf, p - packet_buf);
}

void
player_spawn(connection* con, character_data* c)
{
	u8* p = p_new(out_player_spawn, packet_buf);
	p_encode4(&p, c->id);
	p_encode_str(&p, c->name);

	p_encode_str(&p, ""); // guild
	p_encode2(&p, 0); // guild logo bg
	p_encode1(&p, 0); // guild logo bg color
	p_encode2(&p, 0); // guild logo
	p_encode1(&p, 0); // guild logo color

	// TODO: map buffs

	// this is a giant bitmask that contains which types of buffs are active
	for (u8 i = 0; i < buff_bitmask_bytes; ++i) {
		p_encode1(&p, 0);
	}

	p_encode1(&p, 0);
	p_encode1(&p, 0);

	p_encode2(&p, c->job);
	char_data_encode_look(&p, c);
	p_encode4(&p, 0);
	p_encode4(&p, 0); // item effect TODO
	p_encode4(&p, 0); // chair TODO
	p_encode2(&p, c->x);
	p_encode2(&p, c->y);
	p_encode1(&p, c->stance);
	p_encode2(&p, c->foothold);
	p_encode1(&p, 0);

	// TODO: summoned pets
	p_encode1(&p, 0); // summoned pet list terminator

	// TODO: mount info
	p_encode4(&p, 0); // mount level
	p_encode4(&p, 0); // mount exp
	p_encode4(&p, 0); // mount tiredness

	p_encode1(&p, 0); // player room TODO
	p_encode1(&p, 0); // chalkboard TODO
	
	p_encode1(&p, 0); // crush ring TODO
	p_encode1(&p, 0); // friends ring TODO
	p_encode1(&p, 0); // marriage ring TODO

	p_encode1(&p, 0);
	p_encode1(&p, 0);
	p_encode1(&p, 0);

	maple_write(con, packet_buf, p - packet_buf);
}

#define movement_normal1		0
#define movement_jump			1
#define movement_knockback		2
#define movement_unk1			3
#define movement_teleport		4
#define movement_normal2		5
#define movement_flashjump		6
#define movement_assaulter		7
#define movement_assassinate	8
#define movement_rush			9
#define movement_falling		10
#define movement_chair			11
#define movement_excessive_kb	12
#define movement_recoil_shot	13
#define movement_unk2			14
#define movement_jump_down		15
#define movement_wings			16
#define movement_wings_falling	17

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

void
movement_data_apply(movement_data* m, u8 nmovements, character_data* c)
{
	movement_data* last_mov = &m[nmovements - 1];
	c->x = last_mov->x;
	c->y = last_mov->y;
	c->stance = last_mov->stance;
	c->foothold = last_mov->foothold;
}

u8
movement_data_decode(u8** p, movement_data* movements)
{
	u8 count = p_decode1(p);

	for (u8 i = 0; i < count; ++i)
	{
		movement_data* m = &movements[i];

		u8 type = p_decode1(p);
		m->type = type; // TODO: check if same as stance

		switch (type)
		{
			case movement_falling:
				m->as_falling.unk1 = p_decode1(p);
				break;

			case movement_wings:
			case movement_excessive_kb:
				m->as_wings.unk1 = p_decode1(p);
				m->as_wings.unk2 = p_decode2(p);
				m->as_wings.unk3 = p_decode4(p);
				break;

			case movement_wings_falling:
				m->x = p_decode2(p);
				m->y = p_decode2(p);
				m->foothold = p_decode2(p);
				m->stance = p_decode1(p);
				m->as_wings_falling.unk1 = p_decode2(p);
				m->as_wings_falling.unk2 = p_decode2(p);
				m->as_wings_falling.unk3 = p_decode2(p);
				break;

			case movement_unk2:
				m->as_unk2.unk1 = p_decode1(p);
				m->as_unk2.unk2 = p_decode4(p);
				m->as_unk2.unk3 = p_decode4(p);
				break;

			case movement_normal1:
			case movement_normal2:
				m->x = p_decode2(p);
				m->y = p_decode2(p);
				m->as_normal1.unk1 = p_decode4(p);
				m->foothold = p_decode2(p);
				m->stance = p_decode1(p);
				m->as_normal1.unk2 = p_decode2(p);
				break;

			case movement_jump:
			case movement_knockback:
			case movement_flashjump:
			case movement_recoil_shot:
				m->x = p_decode2(p);
				m->y = p_decode2(p);
				m->stance = p_decode1(p);
				m->foothold = p_decode2(p);
				break;

			case movement_jump_down:
				m->x = p_decode2(p);
				m->y = p_decode2(p);
				m->as_jump_down.unk1 = p_decode2(p);
				m->as_jump_down.unk2 = p_decode4(p);
				m->foothold = p_decode2(p);
				m->stance = p_decode1(p);
				m->as_jump_down.unk3 = p_decode2(p);
				break;

			case movement_chair:
				m->x = p_decode2(p);
				m->y = p_decode2(p);
				m->foothold = p_decode2(p);
				m->stance = p_decode1(p);
				m->as_chair.unk1 = p_decode2(p);
				break;

			case movement_unk1:
			case movement_teleport:
			case movement_assaulter:
			case movement_assassinate:
			case movement_rush:
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

void
movement_data_encode(u8** p, movement_data* movements, u8 nmovements)
{
	p_encode1(p, nmovements);

	for (u8 i = 0; i < nmovements; ++i)
	{
		movement_data* m = &movements[i];
		p_encode1(p, m->type);

		switch (m->type)
		{
			case movement_falling:
				p_encode1(p, m->as_falling.unk1);
				break;

			case movement_wings:
			case movement_excessive_kb:
				p_encode1(p, m->as_wings.unk1);
				p_encode2(p, m->as_wings.unk2);
				p_encode4(p, m->as_wings.unk3);
				// same mem layout as excessive_kb
				break;

			case movement_wings_falling:
				p_encode2(p, m->x);
				p_encode2(p, m->y);
				p_encode2(p, m->foothold);
				p_encode1(p, m->stance);
				p_encode2(p, m->as_wings_falling.unk1);
				p_encode2(p, m->as_wings_falling.unk2);
				p_encode2(p, m->as_wings_falling.unk3);
				break;

			case movement_unk2:
				p_encode1(p, m->as_unk2.unk1);
				p_encode4(p, m->as_unk2.unk2);
				p_encode4(p, m->as_unk2.unk3);
				break;

			case movement_normal1:
			case movement_normal2:
				p_encode2(p, m->x);
				p_encode2(p, m->y);
				p_encode4(p, m->as_normal1.unk1);
				p_encode2(p, m->foothold);
				p_encode1(p, m->stance);
				p_encode2(p, m->as_normal1.unk2);
				break;

			case movement_jump:
			case movement_knockback:
			case movement_flashjump:
			case movement_recoil_shot:
				p_encode2(p, m->x);
				p_encode2(p, m->y);
				p_encode1(p, m->stance);
				p_encode2(p, m->foothold);
				break;

			case movement_jump_down:
				p_encode2(p, m->x);
				p_encode2(p, m->y);
				p_encode2(p, m->as_jump_down.unk1);
				p_encode4(p, m->as_jump_down.unk2);
				p_encode2(p, m->foothold);
				p_encode1(p, m->stance);
				p_encode2(p, m->as_jump_down.unk3);
				break;

			case movement_chair:
				p_encode2(p, m->x);
				p_encode2(p, m->y);
				p_encode2(p, m->foothold);
				p_encode1(p, m->stance);
				p_encode2(p, m->as_chair.unk1);
				break;

			case movement_unk1:
			case movement_teleport:
			case movement_assaulter:
			case movement_assassinate:
			case movement_rush:
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

void
show_moving(connection* con, u32 player_id, movement_data* m, u8 nmovements)
{
	u8* p = p_new(out_player_movement, packet_buf);
	p_encode4(&p, player_id);
	p_encode4(&p, 0);
	movement_data_encode(&p, m, nmovements);

	maple_write(con, packet_buf, p - packet_buf);
}

#define server_message_notice			0
#define server_message_popup			1
#define server_message_mega				2
#define server_message_smega			3
#define server_message_scrolling_hdr	4
#define server_message_pink_text		5
#define server_message_light_blue_text	6

void
scrolling_header(connection* con, char* header)
{
	u8* p = p_new(out_server_message, packet_buf);
	p_encode1(&p, server_message_scrolling_hdr);
	p_encode1(&p, 1);
	p_encode_str(&p, header);

	maple_write(con, packet_buf, p - packet_buf);
}

// ---

u16
get_hardcoded_characters(character_data* ch)
{
	u16 nchars = 1;

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

	ch->cover_equips[equip_helm].expire_time = item_no_expiration;
	ch->cover_equips[equip_helm].id = 1002193;
	ch->cover_equips[equip_helm].type = item_equip;

	ch->cover_equips[equip_top].expire_time = item_no_expiration;
	ch->cover_equips[equip_top].id = 1052040;
	ch->cover_equips[equip_top].type = item_equip;

	ch->equips[equip_top].expire_time = item_no_expiration;
	ch->equips[equip_top].id = 1040002;
	ch->equips[equip_top].type = item_equip;

	ch->equips[equip_bottom].expire_time = item_no_expiration;
	ch->equips[equip_bottom].id = 1060006;
	ch->equips[equip_bottom].type = item_equip;

	ch->equips[equip_shoe].expire_time = item_no_expiration;
	ch->equips[equip_shoe].id = 1072001;
	ch->equips[equip_shoe].type = item_equip;
	ch->equips[equip_shoe].as_equip.jump = 500;
	ch->equips[equip_shoe].as_equip.speed = 500;

	ch->equips[equip_weapon].expire_time = item_no_expiration;
	ch->equips[equip_weapon].id = 1302000;
	ch->equips[equip_weapon].type = item_equip;

	ch->inventory[inv_equip - 1][0].expire_time = item_no_expiration;
	ch->inventory[inv_equip - 1][0].id = 1302000;
	ch->inventory[inv_equip - 1][0].type = item_equip;

	ch->inventory[inv_cash - 1][0].expire_time = unix_now() + 90 * 24 * 60 * 60;
	ch->inventory[inv_cash - 1][0].id = 5000000;
	ch->inventory[inv_cash - 1][0].type = item_pet;

	for (u8 i = 1; i <= ninventories; ++i) {
		ch->inv_capacity[i - 1] = max_inv_slots;
	}

	return nchars;
}

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
	channel_data channels[max_channels];
}
world_data;

global_var
u8 nhardcoded_worlds;

global_var
world_data hardcoded_worlds[max_worlds];

u8
get_hardcoded_worlds(world_data* w)
{
	u8 nworlds = 1;
	u16 baseport = 7200;

	strcpy(w->name, "Meme World 0");
	w->ribbon = ribbon_no;
	w->exp_percent = 100;
	w->drop_percent = 100;
#if 0
	strcpy(w->header, 
		"What the fuck did you just fucking say about me, you little bitch? "
		"I'll have you know I graduated top of my class in the Navy Seals, "
		"and I've been involved in numerous secret raids on Al-Quaeda, and I "
		"have over 300 confirmed kills. I am trained in gorilla warfare and "
		"I'm the top sniper in the entire US armed forces. You are nothing to "
		"me but just another target. I will wipe you the fuck out with "
		"precision the likes of which has never been seen before on this "
		"Earth, mark my fucking words. You think you can get away with saying "
		"that shit to me over the Internet? Think again, fucker. As we speak "
		"I am contacting my secret network of spies across the USA and your "
		"IP is being traced right now so you better prepare for the storm, "
		"maggot. The storm that wipes out the pathetic little thing you call "
		"your life. You're fucking dead, kid. I can be anywhere, anytime, and "
		"I can kill you in over seven hundred ways, and that's just with my "
		"bare hands. Not only am I extensively trained in unarmed combat, but "
		"I have access to the entire arsenal of the United States Marine Corps "
		"and I will use it to its full extent to wipe your miserable ass off "
		"the face of the continent, you little shit. If only you could have "
		"known what unholy retribution your little \"clever\" comment was "
		"about to bring down upon you, maybe you would have held your fucking "
		"tongue. But you couldn't, you didn't, and now you're paying the "
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

	return nworlds;
}

global_var
char* hardcoded_user = "asdasd";

global_var
char* hardcoded_pass = "asdasd";

global_var
u16 hardcoded_char_slots = 3;

typedef struct {
	char user[12];
	b32 logged_in;
	u8 world;
	u8 channel;
	u32 char_id;
	b32 in_game;
}
client_data;

// NOTE: for testing purposes, the server currently only handle 1 player at once
int
login_server(int sockfd, client_data* player)
{
	character_data characters[max_char_slots];
	memset(characters, 0, sizeof(character_data));
	u16 nchars = get_hardcoded_characters(characters);
	
	// ---

	u16 cx1 = 40, cy1 = 300;
	u16 cx2 = 40, cy2 = 190;
	u16 my = cy2 + (cy1 - cy2) / 2;

	world_bubble bubbles[]  = {
		{ 100, 100, "install gentoo" }, 

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
	};

	// ---

	int retcode = 0;

	connection con = {0};
	if (maple_accept(sockfd, &con) < 0) 
	{
		retcode = 1;
		goto cleanup;
	}

	while (1)
	{
		i64 nread = maple_read(&con, packet_buf);
		retcode = nread < 0;
		if (nread <= 0) {
			goto cleanup;
		}

		u8* p = packet_buf;
		u16 hdr = p_decode2(&p);

		switch (hdr)
		{
		case in_login_password:
			p_decode_str(&p, fmtbuf);

			// ignore retarded long usernames
			if (strlen(fmtbuf) > sizeof(player->user) - 1) 
			{
				login_failed(&con, login_not_registered);
				break;
			}

			if (!streq(fmtbuf, hardcoded_user)) 
			{
				char* p = fmtbuf;
				for (; *p && *p < '0' && *p > '9'; ++p);

				if (strstr(fmtbuf, "error") == fmtbuf) 
				{
					u64 reason;

					if (atoui(p, 10, &reason) < 0) {
						login_failed(&con, login_not_registered);
						break;
					}
					
					login_failed(&con, (u32)reason);
				}

				if (strstr(fmtbuf, "ban") == fmtbuf) 
				{
					u64 reason;

					if (atoui(p, 10, &reason) < 0) {
						login_failed(&con, login_not_registered);
						break;
					}
					
					login_banned(
						&con, 
						(u32)reason, 
						unix_to_filetime(
							unix_now() + 2 * 365 * 24 * 60 * 60
						)
					);
				}

				else {
					login_failed(&con, login_not_registered);
				}
				
				break;
			}

			strcpy(player->user, fmtbuf);

			// password
			p_decode_str(&p, fmtbuf);

			if (!streq(fmtbuf, hardcoded_pass)) {
				login_failed(&con, login_incorrect_password);
				break;
			}

			player->logged_in = 1;
			auth_success_request_pin(&con, player->user);
			break;

		// ---------------------------------------------------------------------

		case in_after_login:
			pin_operation(&con, pin_accepted); // FUCK pins
			break;

		// ---------------------------------------------------------------------

		case in_server_list_request:
		case in_server_list_rerequest: // why the fuck are there 2 hdrs for this
		{
			for (u8 i = 0; i < nhardcoded_worlds; ++i)
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
					world_entry_append_channel(
						&p, 
						i, 
						j, 
						ch->name, 
						ch->population
					);
				}

				world_entry_end(&con, p, array_count(bubbles), bubbles);
			}

			world_list_end(&con);
			break;
		}

		// ---------------------------------------------------------------------

		case in_server_status_request:
		{
			u8 worldid = p_decode1(&p);
			player->world = worldid;
			server_status(&con, server_normal);
			break;
		}

		// ---------------------------------------------------------------------

		case in_view_all_char:
		{
			// note this should actually send the number of all chars in every
			// world
			all_chars_count(&con, nchars, nchars + 3 - nchars % 3);
			u8* p = all_chars_begin(0, nchars);

			for (u16 i = 0; i < nchars; ++i) {
				char_data_encode(&p, &characters[i]);
			}

			all_chars_end(&con, p);
				
			break;
		}

		// ---------------------------------------------------------------------

		case in_relog:
			relog_response(&con);
			break;

		// ---------------------------------------------------------------------

		case in_charlist_request:
		{
			u8 worldid = p_decode1(&p);
			u8 channelid = p_decode1(&p);

			if (worldid != player->world) 
			{
				prln("Dropping client for trying to "
					 "select another world's chan");
				goto cleanup;
			}

			player->channel = channelid;

			u8* p = world_chars_begin(nchars);

			for (u16 i = 0; i < nchars; ++i) {
				char_data_encode(&p, &characters[i]);
			}

			world_chars_end(&con, p, hardcoded_char_slots);
			break;
		}

		// ---------------------------------------------------------------------

		case in_char_select:
		{
			player->char_id = p_decode4(&p);

			u8 ip[4] = { 127, 0, 0, 1 };
			connect_ip(
				&con, 
				ip, 
				hardcoded_worlds[player->world].channels[player->channel].port, 
				player->char_id
			);
			break;
		}

		// ---------------------------------------------------------------------

		case in_check_char_name:
			p_decode_str(&p, fmtbuf);
			char_name_response(&con, fmtbuf, 1);
			// TODO: char creation
			break;

		// ---------------------------------------------------------------------

		}
	}

cleanup:
	maple_close(&con);

	return retcode;
}

int
channel_server(int sockfd, client_data* player)
{
	character_data characters[max_char_slots];
	memset(characters, 0, sizeof(character_data));
	get_hardcoded_characters(characters);

	// ---
	
	b32 bot_spawned = 0;
	character_data bot = characters[0];
	bot.id = 2;
	bot.face = 20000;
	bot.hair = 30000;
	memset(bot.cover_equips, 0, sizeof(bot.cover_equips));
	strcpy(bot.name, "Slave");

	// ---

	int retcode = 0;

	connection con = {0};
	if (maple_accept(sockfd, &con) < 0) 
	{
		retcode = 1;
		goto cleanup;
	}

	while (1)
	{
		i64 nread = maple_read(&con, packet_buf);
		retcode = nread < 0;
		if (nread <= 0) {
			goto cleanup;
		}

		u8* p = packet_buf;
		u16 hdr = p_decode2(&p);

		if (!player->in_game) 
		{
			if (hdr != in_player_load) {
				// refuse every packet until the character is loaded
				continue;
			}

			u32 char_id = p_decode4(&p);
			if (char_id != player->char_id) 
			{
				prln("Dropped client that was trying to perform remote hack");
				goto cleanup;
			}

			// TODO: grab correct char from list
			connect_data(&con, player->channel, &characters[0]);

			char* header = hardcoded_worlds[player->world].header;
			if (strlen(header)) {
				scrolling_header(&con, header);
			}

			player->in_game = 1;

			continue;
		}

		switch (hdr)
		{

		case in_player_move:
		{
			/*u8 portal_count = */p_decode1(&p);
			p_decode4(&p);

			movement_data m[255];
			u8 nmovements = movement_data_decode(&p, m);

			// TODO: grab correct char from list
			movement_data_apply(m, nmovements, &characters[0]);
			movement_data_apply(m, nmovements, &bot);

			if (!bot_spawned) {
				player_spawn(&con, &bot);
				bot_spawned = 1;
			}

			show_moving(&con, bot.id, m, nmovements);
			break;
		}

		// ---------------------------------------------------------------------

		case in_player_info:
		{
			// when a character is double clicked

			p_decode4(&p); // tick count
			u32 id = p_decode4(&p);
			
			if (id == bot.id) {
				player_info(&con, &bot, 0);
			} 
			else if (id == player->char_id) {
				// TODO: grab correct char from list
				player_info(&con, &characters[0], 1);
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

int
main()
{
	prln("JunoMS pre-alpha v0.0.14");

	client_data player;

	nhardcoded_worlds = get_hardcoded_worlds(hardcoded_worlds);

	while (1)
	{
		prln("# Login Server");

		int sockfd = tcp_socket(8484);
		if (sockfd < 0) {
			return 1;
		}

		while (!player.char_id || !player.logged_in) {
			memset(&player, 0, sizeof(player));
			if (login_server(sockfd, &player)) {
				return 1;
			}
		}

		close(sockfd);

		// ---

		prln("# Channel Server");

		sockfd = tcp_socket(
				hardcoded_worlds[player.world]
					.channels[player.channel].port);

		if (sockfd < 0) {
			return 1;
		}

		if (channel_server(sockfd, &player)) {
			return 1;
		}

		close(sockfd);
	}

	return 0;
}


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

#define array_count(a) (sizeof(a) / sizeof((a)[0]))

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
u64 epoch_diff = 116444736000000000LL;

u64
unix_to_filetime(u64 unix_seconds) {
	return epoch_diff + unix_seconds * 1000LL * 10000LL;
}

u64
filetime_to_unix(u64 filetime) {
	return (filetime - epoch_diff) / (1000LL * 10000LL);
}

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

typedef struct 
{
	int fd;
	u8 iv_send[4];
	u8 iv_recv[4];
}
connection;

i64
read_all(connection* con, void* dst, u64 nbytes)
{
	u64 nread = 0;

	while (nread < nbytes)
	{
		i64 cb = read(con->fd, dst, nbytes);
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
recv(connection* con, u8* dst)
{
	i64 nread;
	u32 encrypted_hdr;

	// encrypted header
	nread = read_all(con, &encrypted_hdr, maple_encrypted_hdr_size);
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
	nread = read_all(con, dst, packet_len);
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
send(connection* con, u8* packet, u16 nbytes)
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
#define out_handshake	0x000D
#define out_ping		0x0011

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
#define in_check_char_name			0x0016
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
#define in_load_character		0x0014
#define in_player_update		0x00C0
#define in_change_map_special	0x005C
#define in_change_map			0x0023
#define in_move_player			0x0026

#define out_warp_to_map			0x005C
#define out_server_message		0x0041
#define out_change_channel		0x0010
#define out_update_stats		0x001C

void
ping(connection* con)
{
	u8* p = p_new(out_ping, packet_buf);
	send(con, packet_buf, p - packet_buf);
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

	send(con, packet_buf, p - packet_buf);
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

	send(con, packet_buf, p - packet_buf);
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

	send(con, packet_buf, p - packet_buf);
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

	send(con, packet_buf, p - packet_buf);
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

void
world_entry_end(connection* con, u8* p)
{
	p_encode2(&p, 0); // this is supposed to be a message list but it doesn't 
					  // seem to work in v62

	send(con, packet_buf, p - packet_buf);
}

void
world_list_end(connection* con)
{
	u8* p = p_new(out_server_list, packet_buf);
	p_encode1(&p, 0xFF);
	send(con, packet_buf, p - packet_buf);
}

#define server_normal	0
#define server_high		1
#define server_full		2

void
server_status(connection* con, u16 status)
{
	u8* p = p_new(out_server_status, packet_buf);
	p_encode2(&p, status);
	send(con, packet_buf, p - packet_buf);
}

void
all_chars_count(connection* con, u32 nworlds, u32 last_visible_char_slot)
{
	u8* p = p_new(out_all_char_list, packet_buf);
	p_encode1(&p, 1);
	p_encode4(&p, nworlds);
	p_encode4(&p, last_visible_char_slot);
	send(con, packet_buf, p - packet_buf);
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

typedef struct
{
	u32 id;
	i16 slot;
}
equip_data;

#define equipped_slots 51

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

#define sex_otokonoko	0
#define sex_onnanoko	1 // fucking weeb

typedef struct
{
	u32 id;
	char name[13];
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

	u8 nequips;
	equip_data equips[equipped_slots];

	u32 world_rank;
	i32 world_rank_move;
	u32 job_rank;
	i32 job_rank_move;
}
character_data;

void
char_data_encode(u8** p, character_data* c)
{
	u8 huehue[24] = {0};

	p_encode4(p, c->id);
	p_append(p, c->name, sizeof(c->name));
	p_encode1(p, c->gender);
	p_encode1(p, c->skin);
	p_encode4(p, c->face);
	p_encode4(p, c->hair);
	p_append(p, huehue, sizeof(huehue));
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

	// equips
	p_encode1(p, c->gender);
	p_encode1(p, c->skin);
	p_encode4(p, c->face);
	p_encode1(p, 0);
	p_encode4(p, c->hair);

	// TODO: figure out how the fuck this works and rewrite it
	u32 equips[equipped_slots][2];
	memset(equips, 0, sizeof(equips));

	// index 0 is visible/covering equips?
	// index 1 is normal/covered equips?

	for (u8 i = 0; i < c->nequips; ++i)
	{
		equip_data* eq = &c->equips[i];

		// -100 to -151 is normal/covered equips?
		// 0 to 51 is cash/cover stuff?
		i16 slot = -eq->slot;

		if (slot > 100) {
			slot -= 100;
		}

		if (equips[slot][0]) 
		{
			if (eq->slot < -100) 
			{
				// non-covering item?
				equips[slot][1] = equips[slot][0];
				equips[slot][0] = eq->id;
			} else {
				// covering item?
				equips[slot][1] = eq->id;
			}
		}

		else {
			// no equip in this slot yet, just copy the id over
			equips[slot][0] = eq->id;
		}
	}

	// visible equips
	for (u8 i = 0; i < equipped_slots; ++i)
	{
		if (!equips[i][0]) {
			continue;
		}

		p_encode1(p, i);
		
		if (i == equip_weapon && equips[i][1]) {
			p_encode4(p, equips[i][1]); // normal weapons always here
		} else {
			p_encode4(p, equips[i][0]);
		}
	}

	p_encode1(p, 0xFF);

	// covered equips
	for (u8 i = 0; i < equipped_slots; ++i)
	{
		if (equips[i][1] && i != equip_weapon)
		{
			p_encode1(p, i);
			p_encode4(p, equips[i][1]);
		}
	}

	p_encode1(p, 0xFF);
	p_encode4(p, equips[equip_weapon][0]);

	u8 ayylmao[12] = {0};
	p_append(p, ayylmao, sizeof(ayylmao));

	// rankings
	p_encode1(p, 1);
	p_encode4(p, c->world_rank);
	p_encode4(p, (u32)c->world_rank_move);
	p_encode4(p, c->job_rank);
	p_encode4(p, (u32)c->job_rank_move);
	// TODO: why does job rank display incorrectly?
}

void
all_chars_end(connection* con, u8* p) {
	send(con, packet_buf, p - packet_buf);
}

void
relog_response(connection* con) 
{
	u8* p = p_new(out_relog_response, packet_buf);
	p_encode1(&p, 1);
	send(con, packet_buf, p - packet_buf);
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
	send(con, packet_buf, p - packet_buf);
}

void
char_name_response(connection* con, char* name, b32 used)
{
	u8* p = p_new(out_char_name_response, packet_buf);
	p_encode_str(&p, name);
	p_encode1(&p, used ? 1 : 0);
	send(con, packet_buf, p - packet_buf);
}

int
main()
{
	prln("JunoMS pre-alpha v0.0.5");

	int sockfd = socket(af_inet, sock_stream, ipproto_tcp);
	if (sockfd < 0) {
		die("Failed to create socket");
		return 1;
	}

	sockaddr_in serv_addr = {0};
	serv_addr.family = af_inet;
	serv_addr.port = letobe16u(8484);

	if (bind(sockfd, &serv_addr) < 0) {
		die("Failed to bind address to socket");
		return 1;
	}

	if (listen(sockfd, 10) < 0) {
		die("Failed to listen on socket");
		return 1;
	}

	prln("Listening...");

	connection con = {0};

	sockaddr_in client_addr = {0};
	con.fd = accept(sockfd, &client_addr);
	if (con.fd < 0) {
		die("Failed to accept connection from client");
		return 1;
	}

	prln("Client connected");

	if (getrandom(con.iv_recv, 4, 0) != 4 || getrandom(con.iv_send, 4, 0) != 4) 
	{
		die("Failed to generate random IV's");
		return 1;
	}

	// ---

	// build handshake packet
	u8* p = p_new(out_handshake, packet_buf);
	p_encode4(&p, maple_version); // maple version
	p_append(&p, con.iv_recv, 4); 
	p_append(&p, con.iv_send, 4); 
	p_encode1(&p, 8); // region

	tcp_force_flush(con.fd, 1);
	if (write(con.fd, packet_buf, p - packet_buf) < 0) {
		die("Failed to send handshake packet");
		return 1;
	}
	tcp_force_flush(con.fd, 0);

#if JMS_DEBUG_SEND
	puts("Sent handshake packet: ");
	print_bytes(packet_buf, p - packet_buf);
	puts("\n");
#endif

	// ---
	
	character_data ch;
	memset(&ch, 0, sizeof(character_data));

	strcpy(ch.name, "weebweeb");
	ch.level = 200,
	ch.str = 1337,
	ch.dex = 1337,
	ch.intt = 1337,
	ch.luk = 1337,
	ch.hp = 6969,
	ch.maxhp = 6969,
	ch.mp = 727,
	ch.maxmp = 727,
	ch.fame = 1234;
	ch.map = 100000000;
	ch.hair = 30020;
	ch.face = 20000;
	ch.skin = 3;
	ch.id = 1;
	ch.world_rank = 1;
	ch.world_rank_move = 1;
	ch.job_rank = 0;
	ch.job_rank_move = 0;

	ch.nequips = 4;

	ch.equips[0].slot = -equip_top;
	ch.equips[0].id = 1040002;

	ch.equips[1].slot = -equip_bottom;
	ch.equips[1].id = 1060006;

	ch.equips[2].slot = -equip_shoe;
	ch.equips[2].id = 1072001;

	ch.equips[3].slot = -equip_weapon;
	ch.equips[3].id = 1302000;

	// ---

	struct {
		char user[12];
		b32 logged_in;
	} 
	player = {{0}, 0};

	int retcode = 0;
	while (1)
	{
		i64 nread = recv(&con, packet_buf);
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
			if (strlen(fmtbuf) > sizeof(player.user) - 1) 
			{
				login_failed(&con, login_not_registered);
				break;
			}

			puts(fmtbuf);
			prln(" logging in");

			if (!streq(fmtbuf, "asdasd")) 
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
						unix_to_filetime(1474848000LL)
					);
				}

				else {
					login_failed(&con, login_not_registered);
				}
				
				break;
			}

			strcpy(player.user, fmtbuf);

			// password
			p_decode_str(&p, fmtbuf);

			if (!streq(fmtbuf, "asdasd")) {
				login_failed(&con, login_incorrect_password);
				break;
			}

			player.logged_in = 1;
			auth_success_request_pin(&con, player.user);
			break;

		// ---------------------------------------------------------------------

		case in_after_login:
			pin_operation(&con, pin_accepted);
			break;

		// ---------------------------------------------------------------------

		case in_server_list_request:
		case in_server_list_rerequest:
		{
			u8* p = world_entry_begin(
				0, 
				"Memes World 0", 
				ribbon_e, 
				":^)", 
				100, 
				100, 
				2
			);

			// not sure why, but you can't have less than 2 channels ?!
			world_entry_append_channel(&p, 0, 0, "Memes World 0-1", 10);
			world_entry_append_channel(&p, 0, 1, "Memes World 0-2", 0);

			world_entry_end(&con, p);
			world_list_end(&con);
			break;
		}

		// ---------------------------------------------------------------------

		case in_server_status_request:
		{
			u8 worldid = p_decode1(&p);
			
			puts("Selected world ");
			uitoa(10, worldid, fmtbuf, 0, 0);
			prln(fmtbuf);

			server_status(&con, server_normal);
			break;
		}

		// ---------------------------------------------------------------------

		case in_view_all_char:
		{
			all_chars_count(&con, 1, 3);
			u8* p = all_chars_begin(0, 1);
			char_data_encode(&p, &ch);
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
			u8* p = world_chars_begin(1);
			char_data_encode(&p, &ch);
			world_chars_end(&con, p, 3);
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
	close(con.fd);
	close(sockfd);

	return retcode;
}


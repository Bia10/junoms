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
strcpy(char* dst, char* src) {
	memcpy((u8*)dst, (u8*)src, strlen(src) + 1);
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

	i64 offset = chunks * 16;

	for (u8 j = 0; j < 16; ++j) {
		plaintext[j] = output[j] ^ buf[offset + j];
	}

	memcpy(buf + offset, plaintext, nbytes % 16);
	memcpy(input, output, 16);
}

// lol idk some fucked up key routine used to shuffle the iv
void maple_shuffle_iv(u8* iv) {
	unsigned char shit[256] = 
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

void maple_encrypt(u8* buf, u64 nbytes)
{
	u64 j;
	u8 a, c;

	for (u8 i = 0; i < 3; ++i)
	{
		a = 0;

		j = nbytes;
		while (1)
		{
			c = buf[nbytes - j];
			c = rol(c, 3);
			c += j;
			c ^= a;
			a = c;
			c = ror(a, j);
			c ^= 0xFF;
			c += 0x48;
			buf[nbytes - j] = c;

			if (!j) {
				break;
			}

			--j;
		}

		a = 0;

		j = nbytes;
		while (1)
		{
			c = buf[j - 1];
			c = rol(c, 4);
			c += j;
			c ^= a;
			a = c;
			c ^= 0x13;
			c = ror(c, 3);
			buf[j - 1] = c;

			if (!j) {
				break;
			}

			--j;
		}
	}
}

void maple_decrypt(u8* buf, u64 nbytes)
{
	i32 j;
	u8 a, b, c;

	for (u8 i = 0; i < 3; ++i)
	{
		a = 0;
		b = 0;

		j = nbytes;
		while (1)
		{
			c = buf[j - 1];
			c = rol(c, 3);
			c ^= 0x13;
			a = c;
			c ^= b;
			c -= j;
			c = ror(c, 4);
			b = a;
			buf[j - 1] = c;

			if (!j) {
				break;
			}

			--j;
		}

		a = 0;
		b = 0;

		j = nbytes;
		while (1)
		{
			c = buf[nbytes - j];
			c -= 0x48;
			c ^= 0xFF;
			c = rol(c, j);
			a = c;
			c ^= b;
			c -= j;
			c = ror(c, 3);
			b = a;
			buf[nbytes - j] = c;

			if (!j) {
				break;
			}

			--j;
		}
	}
}

#define maple_version 62
#define maple_encrypted_hdr_size 4

u32
maple_encrypted_hdr(u8* iv, u16 nbytes)
{
	u16* low_iv = (u16*)(iv + 2);

	u16 iiv = *low_iv;

	u16 version = maple_version;
	version = 0xFFFF - version;
	iiv ^= version;

	u16 xorediv = iiv ^ nbytes;

	return (u32)xorediv | ((u32)iiv << 16);
}

// ---

// used to build packets everywhere
u8 packet_buf[10000];

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
p_encode2(u8** p, u16 v)
{
	memcpy(*p, &v, 2);
	*p += 2;
}

void
p_encode4(u8** p, u32 v)
{
	memcpy(*p, &v, 4);
	*p += 4;
}

void
p_encode8(u8** p, u64 v)
{
	memcpy(*p, &v, 8);
	*p += 8;
}

void
p_append(u8** p, u8* buf, u64 nbytes)
{
	memcpy(*p, buf, nbytes);
	*p += nbytes;
}

void
p_encode_buf(u8** p, u8* buf, u16 nbytes)
{
	p_encode2(p, nbytes);
	p_append(p, buf, nbytes);
}

void
p_encode_str(u8** p, char* str)
{
	p_encode_buf(p, (u8*)str, strlen(str));
}

// ---

char fmtbuf[1024]; // used to format strings

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

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_SEND
#define dbg_recv_print_encrypted_packet print_bytes_pre
#else
#define dbg_recv_print_encrypted_packet(prefix, buf, nbytes)
#endif

// ---

// NOTE: this is ENCRYPTED send. to send unencrypted data, just use write.
i64
jms_send(int fd, u8* iv_send, u8* packet, u16 nbytes)
{
	u32 encrypted_hdr = maple_encrypted_hdr(iv_send, nbytes);

#if JMS_DEBUG_ENCRYPTION && JMS_DEBUG_RECV
	puts("\n-> Encrypted header ");

	uitoa(16, encrypted_hdr, fmtbuf, 8, '0');
	prln(fmtbuf);
#endif

	if (write(fd, &encrypted_hdr, maple_encrypted_hdr_size) < 0) {
		return -1;
	}
	
	dbg_send_print_packet("->", packet, nbytes);

	maple_encrypt(packet, nbytes);
	dbg_send_print_encrypted_packet("-> Maple Encrypted:", packet, nbytes);

	maple_aes_ofb_transform(packet, iv_send, nbytes);
	dbg_send_print_encrypted_packet("-> Encrypted:", packet, nbytes);

	maple_shuffle_iv(iv_send);

	return write(fd, packet, nbytes);
}

// ---

#define maple_handshake 0x000D

int
main()
{
	prln("JunoMS pre-alpha v0.0.3");

	int sockfd = socket(af_inet, sock_stream, 0);
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

	sockaddr_in client_addr = {0};
	int clientfd = accept(sockfd, &client_addr);
	if (clientfd < 0) {
		die("Failed to accept connection from client");
		return 1;
	}

	prln("Client connected");

	u8 iv_recv[4];
	u8 iv_send[4];

	if (getrandom(iv_recv, 4, 0) != 4 || getrandom(iv_send, 4, 0) != 4) {
		die("Failed to generate random IV's");
		return 1;
	}

	// build handshake packet
	u8* p = p_new(maple_handshake, packet_buf);
	p_encode4(&p, maple_version); // maple version
	p_append(&p, iv_recv, 4); 
	p_append(&p, iv_send, 4); 
	p_encode1(&p, 8); // region

	if (write(clientfd, packet_buf, p - packet_buf) < 0) {
		die("Failed to send handshake packet");
		return 1;
	}

#if JMS_DEBUG_SEND
	puts("Sent handshake packet: ");
	print_bytes(packet_buf, p - packet_buf);
	puts("\n");
#endif

	u32 encrypted_hdr = 0;
	u8 buf[10000]; // used to read the body of the packet

	i64 nread;

	while (1)
	{
		nread = 0;

		while (nread < sizeof(encrypted_hdr))
		{
			i64 cb = read(clientfd, &encrypted_hdr, maple_encrypted_hdr_size);
			if (cb < 0) {
				die("Socket error");
				return 1;
			}

			nread += cb;
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

		nread = 0;
		while (nread < packet_len)
		{
			i64 cb = read(clientfd, buf, 10000);
			if (cb < 0) {
				die("Socket error");
				return 1;
			}

			nread += cb;
		}

		dbg_recv_print_encrypted_packet("<- Encrypted:", buf, packet_len);

		maple_aes_ofb_transform(buf, iv_recv, packet_len);
		dbg_recv_print_encrypted_packet("<- AES Decrypted:", buf, packet_len);

		maple_decrypt(buf, packet_len);
		dbg_recv_print_packet("<-", buf, packet_len);

		maple_shuffle_iv(iv_recv);
	}

	close(clientfd);
	close(sockfd);

	return 0;
}


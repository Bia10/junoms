#include "syscalls.h"

typedef unsigned long long	u64;
typedef unsigned long		u32;
typedef unsigned short		u16;
typedef unsigned char		u8;

typedef long long	i64;
typedef long		i32;
typedef short		i16;
typedef char		i8;

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
fputs(int fd, char* str) {
	return write(fd, str, strlen(str)) + write(fd, "\n", 1);
}

i64 
puts(char* str) {
	return fputs(stdout, str);
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

// ---

void
die(char* msg)
{
	write(stderr, "ORERU: ", 7);
	fputs(stderr, msg);
}

int
main()
{
	puts("JunoMS pre-alpha v0.0.1");

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

	puts("Listening...");

	sockaddr_in client_addr = {0};
	int clientfd = accept(sockfd, &client_addr);
	if (clientfd < 0) {
		die("Failed to accept connection from client");
		return 1;
	}

	puts("Client connected");

	u8 handshake[15];
	u8* p = handshake;
	
	*(u16*)p = 0x000D; // handshake header
	p += 2;

	*(u32*)p = 62; // version
	p += 4;

	if (getrandom(p, 8, 0) != 8) {
		die("Failed to generate random IV's");
		return 1;
	}

	p += 8;

	*p = 8; // GMS region

	if (write(clientfd, handshake, 15) < 0) {
		die("Failed to send handshake packet");
		return 1;
	}

	u8 buf[0xFFFF];
	i64 cb;
	while ((cb = read(clientfd, buf, 0xFFFF)) >= 0)
	{
		// ...
	}

	close(clientfd);
	close(sockfd);

	return 0;
}


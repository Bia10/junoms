#pragma once

#define SYS_read			0
#define SYS_write 			1
#define SYS_close 			3

#define SYS_socket			41
#define SYS_connect			42
#define SYS_accept			43
#define SYS_bind			49
#define SYS_listen			50
#define SYS_setsockopt		54

#define SYS_exit 			60
#define SYS_kill			62

#define SYS_clock_gettime	228
#define SYS_getrandom		318

#ifndef JMS_SYSCALLS_ASM 
typedef unsigned long long syscall_t;

void* 
syscall1(syscall_t number, void* arg);

void* 
syscall2(syscall_t number, void* arg1, void* arg2);

void* 
syscall3(syscall_t number, void* arg1, void* arg2, void* arg3);

void* 
syscall4(syscall_t number, void* arg1, void* arg2, void* arg3, void* arg4);

void*
syscall5(
	syscall_t number, 
	void* arg1, 
	void* arg2, 
	void* arg3, 
	void* arg4, 
	void* arg5
);
#endif

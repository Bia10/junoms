#!/bin/sh

gcc 													\
	linux_junoms.S linux_junoms.c						\
	-std=c99 -Wall -Werror								\
	-fno-builtin -fdata-sections -fno-stack-protector	\
	-Wl,--gc-sections -nostdlib							\
	-O2 												\
	-o juno

strip -R .eh_frame -R .eh_frame_hdr -R .comment juno

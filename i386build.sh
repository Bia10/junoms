#!/bin/sh

#   This code is public domain and comes with no warranty.
#   You are free to do whatever you want with it. You can
#   contact me at lolisamurai@tfwno.gf but don't expect any
#   support.
#   I hope you will find the code useful or at least
#   interesting to read. Have fun!
#   -----------------------------------------------------------
#   This file is part of "junoms", a maplestory server emulator

exename=juno

gcc \
    i386/start.S i386/main.c \
    -m32 -std=c99 -O2 \
    -Wall -Werror -Wno-long-long \
    -fdata-sections \
    -fno-stack-protector \
    -Wl,--gc-sections \
    -fno-unwind-tables \
    -fno-asynchronous-unwind-tables \
    -Wa,--noexecstack \
    -fno-builtin \
    -nostdlib \
    -DJMS_DEBUG_SEND=1 \
    -DJMS_DEBUG_RECV=1 \
    -DJMS_DEBUG_ENCRYPTION=0 \
    -DJMS_TCP_NODELAY=0 \
    -DJMS_DRAW_DICK=0 \
    -DJMS_NAVYSEALS=0 \
    -o $exename \
\
&& strip \
    -R .eh_frame \
    -R .eh_frame_hdr \
    -R .comment \
    $exename

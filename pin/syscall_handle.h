#ifndef __SYSCALL_HANDLE_H__
#define __SYSCALL_HANDLE_H__

#endif

#include "pin.H"
#include "shadow_map.h"

#define BRK_SYSCALL 45
#define MUNMAP_SYSCALL 91
#define MMAP_SYSCALL 192

void syscall_enter(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v);
void syscall_exit(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v);

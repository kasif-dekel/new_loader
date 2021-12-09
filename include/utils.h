#ifndef UTILS_H
#define UTILS_H
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <poll.h>

#define FORKSRV_FD  198
#define AREA_BASE   ((uint8_t *)0x200000)
#define AREA_SIZE   ((size_t)1 << 16)
#define bool int
#define false 0 
#define true 1
#define PROCMAPS_LINE_MAX_LENGTH  (PATH_MAX + 100) 


static void print_message(bool fatal, const char *msg, ...);
#define error(msg, ...)                                             \
    print_message(true, "e9afl runtime error: " msg "\n", ## __VA_ARGS__)
#define log(msg, ...)                                               \
    print_message(false, "e9afl log: " msg "\n", ## __VA_ARGS__)


typedef struct handle {
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    uint8_t* mem;
    void* base_address;
} handle_t;



typedef struct __attribute__((packed)) __attribute__((aligned(4))) data_buffer {
    void* _vftbl;
    unsigned long long field_8;
    unsigned long long field_10;
    unsigned long long field_18;
    unsigned long long field_20;
    unsigned long long field_28;
    unsigned long long field_30;
    unsigned long long field_38;
    unsigned long long field_40;
    unsigned long long field_48;
    unsigned long long cursor;
    unsigned long long data_len;
    unsigned long long total_data_len;
    void* data_ptr;
    void* data_ptr_end;
    void* curr_data_ptr;
    int field_80;
} data_buffer_t;



typedef struct __attribute__((packed)) __attribute__((aligned(1))) jump_struct {
    unsigned char moveopcode[2];
    unsigned long long address;
    unsigned char pushorjump[3];
} jump_struct_t;



void parse_split_line(char* buf, char* addr1, char* addr2, char* perm, char* offset, char* device, char* inode, char* pathname);
data_buffer_t* create_data_buffer(unsigned char* buffer, unsigned int len);
handle_t* create_module_handle(void* base_address, char* binary_path);
void __afl_start_forkserver(void);
void __afl_map_shm(void);
void* get_lib_addr(char* libname);
void* lookup_symbol(handle_t* h, const char* symname);
void closesockets();
int prepare_fuzzer(void* res, void* dissection_context);
#endif
#include "./include/utils.h"

typedef void* (*create_parser_t)(void*);
typedef data_buffer_t* (*data_buffer_constructor_t)(data_buffer_t*);
typedef void* (*process_layer_t)(void* parser_result, void* base_parser, void* dissection_context, data_buffer_t* data_buffer);

int should_hook = 0;
void* lib_baseaddr = NULL;
int done_hooking = 0;
void* horizon_baseaddr = NULL;
int did_hook_happened = 0;
int should_end_poll = 0;
unsigned long long addr_to_returnto;

data_buffer_constructor_t data_buffer_construct_ptr;

#define INSTRUMENTED_OFFSET 0x7fdbc000
#define HORIZON_PATH "/opt/horizon/bin/horizon"
#define CALL_PROCESS_HOOK_OFFSET (0xdf2a0)
#define UDP_TRAFFIC_PATH "/tmp/fuzzer/udp.pcap"


data_buffer_t* create_data_buffer(unsigned char* buffer, unsigned int len) {
    printf("data buffer size: %ld\n", sizeof(data_buffer_t));
    data_buffer_t* data_buffer = malloc(sizeof(data_buffer_t));

    if (data_buffer == NULL) {
        printf("Failed to allocate data buffer\n");
        return NULL;
    }

    data_buffer_construct_ptr(data_buffer);

    data_buffer->cursor = 0;
    data_buffer->data_len = len;
    data_buffer->total_data_len = len;
    data_buffer->data_ptr = buffer;
    data_buffer->data_ptr_end = &buffer[len];
    data_buffer->curr_data_ptr = buffer;

    return data_buffer;
}

__attribute__((naked)) void trampoline() {
    __asm__(
        ".intel_syntax;"
        "push %%rax;" //backup rax
        "mov %%eax, [%%rsi+0x10];"
#ifdef IS_UDP
        "cmp %%eax, 0xe23ff64c;" // DNS CONST, for UDP
#else
        "cmp %%eax, 0x3d829631;" // HTTP CONST, for TCP
#endif
        "pop %%rax;" //restore rax
        "jz prepare_fuzzer;"
        "push %%rbp;"
        "push %%rbx;"
        "sub %%rsp, 0x1b8;"
        "mov [%%rsp], %%rdi;"
        "mov %%rdi, %0;"
        "jmp %%rdi;"
        ".att_syntax;"
        :: "p" (addr_to_returnto)
    );
}


int prepare_fuzzer(void* res, void* dissection_context) {
    if (did_hook_happened) {
        while (true) {
            sleep(1000);
        }
    }
    did_hook_happened = 1;
    char* fuzzbuffer = 0;
    long length;


    int ret_val = 0;
    create_parser_t create_parser_addr = NULL;

    const char* target_fuzzee = getenv("__TARGET_FUZZEE");
    const char* target_path = getenv("__TARGET_FUZZEE_PATH");
    const char* target_symbol = getenv("__TARGET_SYMBOL");
    const char* fuzzfile = getenv("__FUZZFILE");

    if (!target_fuzzee || !target_symbol || !target_path || !fuzzfile) {
        printf("Failed to get environment variables target_fuzzee: %s, target_symbol: %s target_path: %s fuzzfile: %s\n", target_fuzzee, target_symbol, target_path, fuzzfile);
        ret_val = -1;
        exit(ret_val);
    }

    void* real_lib_handle = dlopen(target_path, RTLD_NOW);

    if (real_lib_handle == NULL) {
        printf("Failed to get library handle\n");
        ret_val = -1;
        exit(ret_val);
    }

    printf("lib handle pointer %p\n", real_lib_handle);
    create_parser_addr = dlsym(real_lib_handle, "create_parser");

    if (create_parser_addr == NULL) {
        printf("Failed to get create_parser address\n");
        ret_val = -1;
        exit(ret_val);
    }

    printf("create_parser address %p\n", create_parser_addr);

    unsigned long long test = 0;
    void** create_parser_obj = create_parser_addr(&test);

    printf("create_parser obj  %p\n", *create_parser_obj);

    handle_t* horizon_handle = create_module_handle(horizon_baseaddr, HORIZON_PATH);

    if (horizon_handle == NULL) {
        printf("horizon_handle is NULL \n");
        ret_val = -1;
        exit(ret_val);
    }

    lib_baseaddr = get_lib_addr((char*)target_fuzzee);
    printf("lib_baseaddress %p\n", lib_baseaddr);
    handle_t* lib_handle = create_module_handle(lib_baseaddr, (char*)target_path);

    if (lib_handle == NULL) {
        printf("lib_handle is NULL \n");
        ret_val = -1;
        exit(ret_val);
    }

    data_buffer_construct_ptr = lookup_symbol(horizon_handle, "_ZN7horizon7general10DataBufferC2Ev");
    printf("data_buffer_addr: %p\n", data_buffer_construct_ptr);

    process_layer_t process_layer_ptr = (process_layer_t)lookup_symbol(lib_handle, target_symbol);
    void* parser_result = malloc(100);

    puts("hello from prepare_fuzzer\r\n");

    should_end_poll = 1;
    sleep(1);

    closesockets();

    __afl_map_shm();
    __afl_start_forkserver();

    FILE* f = fopen(fuzzfile, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        fuzzbuffer = malloc(length);
        if (fuzzbuffer) {
            fread(fuzzbuffer, 1, length, f);
        }
        fclose(f);
    }

    if (fuzzbuffer) {
        data_buffer_t* buffer = create_data_buffer((unsigned char*)fuzzbuffer, length);
        process_layer_ptr(parser_result, *create_parser_obj, dissection_context, buffer);
    }

    _exit(0);
}


int hooker() {
    horizon_baseaddr = get_lib_addr("horizon") + INSTRUMENTED_OFFSET;

    printf("horizon_baseaddress %p aligned: %p offset: %x\n", horizon_baseaddr, horizon_baseaddr + (CALL_PROCESS_HOOK_OFFSET & 0xff000), (CALL_PROCESS_HOOK_OFFSET & 0xff000));
    int ret_val = mprotect(horizon_baseaddr + (CALL_PROCESS_HOOK_OFFSET & 0xff000), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (ret_val == -1) {
        printf("Failed to change page permissions\n");
        return -1;
    }

    addr_to_returnto = (unsigned long long)(((char*)horizon_baseaddr) + (CALL_PROCESS_HOOK_OFFSET + 13));
    void* dest = horizon_baseaddr + CALL_PROCESS_HOOK_OFFSET;

    jump_struct_t jump_struct;
    jump_struct.moveopcode[0] = 0x49;
    jump_struct.moveopcode[1] = 0xbb;
    jump_struct.address = (unsigned long long) trampoline;
    jump_struct.pushorjump[0] = 0x41;  
    jump_struct.pushorjump[1] = 0xff;
    jump_struct.pushorjump[2] = 0xe3;

    memcpy(dest, &jump_struct, sizeof(jump_struct_t));
}

#ifdef IS_UDP
typedef void pcap_t;

pcap_t* (*pcap_open_offline_orig)(const char* fname, char* errbuf);
pcap_t* pcap_open_offline(const char* fname, char* errbuf)
{
    if (!pcap_open_offline_orig)
        pcap_open_offline_orig = dlsym(RTLD_NEXT, "pcap_open_offline");

    printf("PCAP FILE: %s\n", fname);
    return pcap_open_offline_orig(UDP_TRAFFIC_PATH, errbuf);
}
#endif

int (*setsockopt_orig)(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen) {
    if (!setsockopt_orig) setsockopt_orig = dlsym(RTLD_NEXT, "setsockopt");
    if (done_hooking || !should_hook) {
        return setsockopt_orig(sockfd, level, optname, optval, optlen);
    }
    done_hooking = 1;
    hooker();

    return setsockopt_orig(sockfd, level, optname, optval, optlen);
}

void (*srand_orig)(unsigned int seed);
void srand(unsigned int seed) {
    if (!srand_orig)
        srand_orig = dlsym(RTLD_NEXT, "srand");
    srand_orig(1);
}

int (*poll_orig)(struct pollfd* fds, nfds_t nfds, int timeout);
int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
    if (!poll_orig)
        poll_orig = dlsym(RTLD_NEXT, "poll");
    if (should_end_poll) {
        pause();
    }

    return poll_orig(fds, nfds, timeout);
}

__attribute__((constructor)) int run() {
    char* current_path = realpath("/proc/self/exe", NULL);

    if (strstr(current_path, HORIZON_PATH) == 0) {
        return -1;
    }

    should_hook = 1;
    return 0;
}




#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/shm.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "./include/utils.h"
#include <dlfcn.h>

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

#define bool int
#define false 0 
#define true 1

typedef void* (*test_t)(char *str);
typedef void* (*create_parser_t)(void*);
typedef data_buffer_t* (*data_buffer_constructor_t)(data_buffer_t*);
handle_t* create_module_handle(void* base_address, char* binary_path);
typedef void* (*process_layer_t)(void* parser_result, void* base_parser, void* dissection_context, data_buffer_t* data_buffer);
//#include "./include/utils.c"

int should_hook = 0;
void* libhttp_baseaddr = NULL;
int done_hooking = 0;
void* horizon_baseaddr = NULL;
int did_hook_happened = 0;

data_buffer_constructor_t data_buffer_construct_ptr;

#define TEST_PACKET "GET / HTTP/1.1\r\nHost: 192.168.0.140\r\n\r\n"
#define HUYINADARABUSH 0x7fdbc000
#define HORIZON_PATH "/opt/horizon/bin/horizon.afl"
#define CALL_PROCESS_HOOK_OFFSET (0xdf2a0) // TODO: verify
#define LIBHTTP_PATH "/opt/horizon/lib/horizon/http/libhttp.so"

static FILE *log = NULL;

static void print_message(bool fatal, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    if (log == NULL)
    {
        log = fopen("/tmp/e9afl.log", "a");
        if (log != NULL)
            setvbuf(log, NULL, _IONBF, 0);
    }
    if (log == NULL)
    {
        if (fatal)
            abort();
        return;
    }
    vfprintf(log, msg, ap);
    if (fatal)
        abort();
    va_end(ap);
}

#define error(msg, ...)                                             \
    print_message(true, "e9afl runtime error: " msg "\n", ## __VA_ARGS__) //TODO: remove
#define log(msg, ...)                                               \
    print_message(false, "e9afl log: " msg "\n", ## __VA_ARGS__)

/* SHM setup. */
static void __afl_map_shm(void)
{
    const char *id_str = getenv("__AFL_SHM_ID");

    /* 
     * If we're running under AFL, attach to the appropriate region,
     * replacing the early-stage __afl_area_initial region that is needed to
     * allow some really hacky .init code to work correctly in projects such
     * as OpenSSL.
     */
    intptr_t afl_area_ptr = 0x0;
    uint32_t shm_id = 0;
    if (id_str != NULL)
    {
        shm_id = (uint32_t)atoi(id_str);
        (void)munmap(AREA_BASE, AREA_SIZE);
        afl_area_ptr = (intptr_t)shmat(shm_id, AREA_BASE, 0);
    }
    else
    {
        /* 
         * If there is no id_str then we are running the program normally
         * and not with afl-fuzz.  Create a dummy area so the program does
         * not crash.
         */
        afl_area_ptr = (intptr_t)mmap(AREA_BASE, AREA_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }

    /* Whooooops. */
    if (afl_area_ptr != (intptr_t)AREA_BASE)
        error("failed to map AFL area (shm_id=%s): %s", id_str,
            strerror(errno));
}

/* Fork server logic. */
static void __afl_start_forkserver(void)
{
    const unsigned char tmp[4] = {0};
    int child_pid;

    /* 
     * Phone home and tell the parent that we're OK. If parent isn't there,
     * assume we're not running in forkserver mode and just execute program.
     */
    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
        return;

    while (true)
    {
        /*
         * Wait for parent by reading from the pipe. Abort if read fails.
         */
        unsigned int was_killed;
        if (read(FORKSRV_FD, &was_killed, sizeof(was_killed))
                != sizeof(was_killed))
            error("failed to read from the fork server pipe: %s",
                strerror(errno));

        int status = 0;
        if (was_killed)
        {
            if (waitpid(child_pid, &status, 0) < 0)
                log("failed to wait for child process: %s", strerror(errno));
        }

        /*
         * Once woken up, create a clone of our process.
         */
        child_pid = fork();
        if (child_pid < 0)
            error("failed to fork process: %s", strerror(errno));

        /*
         * In child process: close fds, resume execution.
         */
        if (!child_pid)
        {
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;
        }

        /*
         * In parent process: write PID to pipe, then wait for child.
         */
        if (write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid))
                != sizeof(child_pid))
            error("failed to write child pid to the fork server pipe: %s",
                strerror(errno));
        if (waitpid(child_pid, &status, 0) < 0)
            log("failed to wait for the child process: %s", strerror(errno));

        /*
         * Relay wait status to pipe, then loop back.
         */
        if (write(FORKSRV_FD + 1, &status, sizeof(status)) != sizeof(status)) 
            error("failed to write child status to the fork server pipe: %s",
                strerror(errno));
    }
}



data_buffer_t* create_data_buffer(unsigned char* buffer, unsigned int len)
{
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


int returnhappend() {
    puts("RETURN HAPPENED!\n\n\n\n");
    fflush(stdin);
}

int prepare_fuzzer(void* res, void* dissection_context) {
    if(did_hook_happened) { 
        while(true) { 
            sleep(1000);
        }
    }
    did_hook_happened = 1;
    char * fuzzbuffer = 0;
    long length;


     int ret_val = 0;
    create_parser_t create_parser_addr = NULL;

    void* real_libhttp_handle = dlopen(LIBHTTP_PATH, RTLD_NOW);

    if (real_libhttp_handle == NULL) {
        printf("Failed to get libhttp.so handle\n");
        ret_val = -1;
        exit(ret_val);
    }

    printf("handle pointer %p\n", real_libhttp_handle);

    create_parser_addr = dlsym(real_libhttp_handle, "create_parser");

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

    libhttp_baseaddr = get_lib_addr("libhttp");
    printf("libhttp_baseaddress %p\n", libhttp_baseaddr);

    handle_t* libhttp_handle = create_module_handle(libhttp_baseaddr, LIBHTTP_PATH);

    if (libhttp_handle == NULL) {
        printf("libhttp_handle is NULL \n");
        ret_val = -1;
        exit(ret_val);
    }

    data_buffer_construct_ptr = lookup_symbol(horizon_handle, "_ZN7horizon7general10DataBufferC2Ev");
    printf("data_buffer_addr: %p\n", data_buffer_construct_ptr);

    data_buffer_t* buffer = create_data_buffer((unsigned char*)TEST_PACKET, strlen(TEST_PACKET));
    // dissection_context_t* context = create_dissection_context();

    process_layer_t process_layer_ptr = (process_layer_t)lookup_symbol(libhttp_handle, "_ZN12_GLOBAL__N_110HTTPParser12processLayerERN7horizon8protocol10management16IProcessingUtilsERNS1_7general11IDataBufferE");

    void* parser_result = malloc(100);


    process_layer_ptr(parser_result, *create_parser_obj, dissection_context, buffer);

    puts("hello from prepare_fuzzer\r\n");
    // libtest_baseaddr = get_lib_addr("libtest");
    // //printf("libtest_baseaddress %p\n", libtest_baseaddr);

    // handle_t* libtest_handle = create_module_handle(libtest_baseaddr, "/mnt/d/projects/fuzz/dissectors/tests/snapshot_tests/shared_lib/libtest.so");

    // if (libtest_handle == NULL) {
    //     puts("err in acquiring libtest_handle\r\n");
    //     return -1;
    // }

    // test_t test_ptr = (test_t)lookup_symbol(libtest_handle, "test");
    // if(!test_ptr) { 
    //     puts("err in acquiring libtest_handle\r\n");
    //     return -1;
    // }
    puts("ABABABABABABABAAB\n");

    //environ = malloc(0x1000);
    //__afl_map_shm();
    // __afl_start_forkserver();

    // FILE * f = fopen ("/tmp/a.txt", "rb");
    // if (f) {
    // fseek (f, 0, SEEK_END);
    // length = ftell (f);
    // fseek (f, 0, SEEK_SET);
    // buffer = malloc(length);
    // if (buffer) {
    //     fread (buffer, 1, length, f);
    // }
    // fclose (f);
    // }

    // if (buffer) {
    // test_ptr(buffer);
    // }
    // exit(0);
    

    _exit(0);
}


int hooker() { 
    horizon_baseaddr = get_lib_addr("horizon.afl") + HUYINADARABUSH;
    
    printf("horizon_baseaddress %p aligned: %p offset: %x\n", horizon_baseaddr, horizon_baseaddr + (CALL_PROCESS_HOOK_OFFSET & 0xff000), (CALL_PROCESS_HOOK_OFFSET & 0xff000));
    int ret_val = mprotect(horizon_baseaddr + (CALL_PROCESS_HOOK_OFFSET & 0xff000), 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    if (ret_val == -1) {
        printf("Failed to change page permissions\n");
        return -1;
    }

    void* dest = horizon_baseaddr + CALL_PROCESS_HOOK_OFFSET;
    jump_struct_t jump_struct;
    jump_struct.moveopcode[0] = 0x48;
    jump_struct.moveopcode[1] = 0xBF;
    jump_struct.address = (unsigned long long) prepare_fuzzer;
    jump_struct.pushret[0] = 0x57;
    jump_struct.pushret[1] = 0xC3;

    memcpy(dest, &jump_struct, sizeof(jump_struct_t));

    
    //returnhappend
}

int (*setsockopt_orig)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);


int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) { 
    if(!setsockopt_orig) setsockopt_orig = dlsym(RTLD_NEXT, "setsockopt");
    if(done_hooking || !should_hook) { 
        return setsockopt_orig(sockfd, level, optname, optval, optlen);
    }

    hooker();


    done_hooking = 1;
    return setsockopt_orig(sockfd, level, optname, optval, optlen);
    
}



__attribute__((constructor)) int run() {
    puts("hello from run\r\n");
    char* current_path = realpath("/proc/self/exe", NULL);

    if (strcmp(current_path, HORIZON_PATH) != 0) {
        return -1;
    }
    should_hook = 1;
    

    return 0;
}




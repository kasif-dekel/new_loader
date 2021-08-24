#include "./include/utils.h"




typedef void* (*create_parser_t)(void*);
typedef data_buffer_t* (*data_buffer_constructor_t)(data_buffer_t*);
typedef void* (*process_layer_t)(void* parser_result, void* base_parser, void* dissection_context, data_buffer_t* data_buffer);


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


int prepare_fuzzer(void* res, void* dissection_context) {
    if(did_hook_happened) { 
        while(true) { 
            sleep(1000);
        }
    }
    did_hook_happened = 1;
    char *fuzzbuffer = 0;
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
    fflush(NULL); //TODO: remove
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
    fflush(NULL); //TODO: remove
    handle_t* libhttp_handle = create_module_handle(libhttp_baseaddr, LIBHTTP_PATH);

    if (libhttp_handle == NULL) {
        printf("libhttp_handle is NULL \n");
        ret_val = -1;
        exit(ret_val);
    }

    data_buffer_construct_ptr = lookup_symbol(horizon_handle, "_ZN7horizon7general10DataBufferC2Ev");
    printf("data_buffer_addr: %p\n", data_buffer_construct_ptr);



    process_layer_t process_layer_ptr = (process_layer_t)lookup_symbol(libhttp_handle, "_ZN12_GLOBAL__N_110HTTPParser12processLayerERN7horizon8protocol10management16IProcessingUtilsERNS1_7general11IDataBufferE");

    void* parser_result = malloc(100);

    puts("hello from prepare_fuzzer\r\n");
    fflush(NULL); //TODO: remove
  


    __afl_map_shm();
    __afl_start_forkserver();

    FILE * f = fopen("/tmp/fuzzfile.txt", "rb");
    if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    fuzzbuffer = malloc(length);
    if (fuzzbuffer) {
        fread (fuzzbuffer, 1, length, f);
    }
    fclose (f);
    }

    if (fuzzbuffer) {
        data_buffer_t* buffer = create_data_buffer((unsigned char*)fuzzbuffer, length);
        process_layer_ptr(parser_result, *create_parser_obj, dissection_context, buffer);
    }
    
    puts("ABABABABABABABAAB\n");
    fflush(NULL); //TODO: remove
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
    fflush(NULL);

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
    done_hooking = 1;
    hooker();


    
    return setsockopt_orig(sockfd, level, optname, optval, optlen);
    
}



__attribute__((constructor)) int run() {
    puts("hello from run\r\n");
    fflush(NULL);
    char* current_path = realpath("/proc/self/exe", NULL);

    if (strcmp(current_path, HORIZON_PATH) != 0) {
        return -1;
    }
    should_hook = 1;
    

    return 0;
}




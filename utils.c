#include "include/utils.h"

// modified code, taken from stackoverflow
void* get_lib_addr(char* libname) {
    void* found_addr = NULL;
    FILE* file = fopen("/proc/self/maps", "r");
    if (file == NULL) {
        printf("Failed to open /proc/self/maps\n");
        goto lbl_cleanup;
    }

    char buf[PROCMAPS_LINE_MAX_LENGTH];

    char addr1[20], addr2[20], perm[8], offset[20], dev[10], inode[30], pathname[PATH_MAX];
    while (!feof(file)) {
        fgets(buf, PROCMAPS_LINE_MAX_LENGTH, file);
        parse_split_line(buf, addr1, addr2, perm, offset, dev, inode, pathname);
        if (strstr(pathname, libname)) {
            sscanf(addr1, "%lx", (long unsigned*)&found_addr);
            goto lbl_cleanup;
        }
    }

lbl_cleanup:
    if (file != NULL)
        fclose(file);

    return found_addr;
}

// modified code, taken from stackoverflow
void parse_split_line(char* buf, char* addr1, char* addr2, char* perm, char* offset, char* device, char* inode, char* pathname) {
    int orig = 0;
    int i = 0;

    while (buf[i] != '-') {
        addr1[i - orig] = buf[i];
        i++;
    }
    addr1[i] = '\0';
    i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        addr2[i - orig] = buf[i];
        i++;
    }
    addr2[i - orig] = '\0';

    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;

    while (buf[i] != '\t' && buf[i] != ' ') {
        perm[i - orig] = buf[i];
        i++;
    }
    perm[i - orig] = '\0';

    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;

    while (buf[i] != '\t' && buf[i] != ' ') {
        offset[i - orig] = buf[i];
        i++;
    }
    offset[i - orig] = '\0';

    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;

    while (buf[i] != '\t' && buf[i] != ' ') {
        device[i - orig] = buf[i];
        i++;
    }
    device[i - orig] = '\0';

    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        inode[i - orig] = buf[i];
        i++;
    }
    inode[i - orig] = '\0';

    pathname[0] = '\0';

    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;

    while (buf[i] != '\t' && buf[i] != ' ' && buf[i] != '\n') {
        pathname[i - orig] = buf[i];
        i++;
    }
    pathname[i - orig] = '\0';

}


void* lookup_symbol(handle_t* h, const char* symname) {
    int i, j;
    char* strtab;
    Elf64_Sym* symtab;

    if (h->base_address == NULL) {
        return NULL;
    }

    for (i = 0; i < h->ehdr->e_shnum; i++) {
        if (h->shdr[i].sh_type == SHT_SYMTAB) {
            strtab = (char*)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
            symtab = (Elf64_Sym*)&h->mem[h->shdr[i].sh_offset];

            for (j = 0; j < h->shdr[i].sh_size / sizeof(Elf64_Sym); j++) {

                if (strcmp(&strtab[symtab->st_name], symname) == 0) {
                    return (void*)(h->base_address + symtab->st_value);
                }
                symtab++;
            }
        }
    }

    return NULL;
}

handle_t* create_module_handle(void* base_address, char* binary_path) {

    handle_t* module_handle = NULL;
    struct stat st;
    int horizon_fd = -1;
    if ((horizon_fd = open(binary_path, O_RDONLY)) < 0) {
        printf("Failed to open horizon\n");
        goto lbl_cleanup;
    }

    if (fstat(horizon_fd, &st) < 0) {
        printf("Failed to stat fd\n");
        goto lbl_cleanup;
    }

    module_handle = (handle_t*)malloc(sizeof(handle_t));

    // PLEASE FREE ME
    if (module_handle == NULL) {
        printf("Failed to allocate handle_t\n");
        goto lbl_cleanup;
    }

    module_handle->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, horizon_fd, 0);

    if (module_handle->mem == MAP_FAILED) {
        printf("Mmap failed\n");
        goto lbl_cleanup;
    }

    module_handle->base_address = base_address;
    module_handle->ehdr = (Elf64_Ehdr*)module_handle->mem;
    module_handle->phdr = (Elf64_Phdr*)(module_handle->mem + module_handle->ehdr->e_phoff);
    module_handle->shdr = (Elf64_Shdr*)(module_handle->mem + module_handle->ehdr->e_shoff);


    if (module_handle->mem[0] != 0x7f) {
        printf("Not an ELF file\n");
        goto lbl_cleanup;
    }

lbl_cleanup:
    return module_handle;
}


static FILE *log = NULL;

// e9afl code
static void print_message(bool fatal, const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    if (log == NULL)
    {   
        char tmp[75];
        sprintf(tmp, "/tmp/e9afl.log.%d", getpid());
        log = fopen(tmp, "a");
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


// e9afl/afl code
void __afl_map_shm(void) {
    const char *id_str = getenv("__AFL_SHM_ID");

    intptr_t afl_area_ptr = 0x0;
    uint32_t shm_id = 0;
    if (id_str != NULL) {
        shm_id = (uint32_t)atoi(id_str);
        (void)munmap(AREA_BASE, AREA_SIZE);
        afl_area_ptr = (intptr_t)shmat(shm_id, AREA_BASE, 0);
    }
    else  {

        afl_area_ptr = (intptr_t)mmap(AREA_BASE, AREA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }


    if (afl_area_ptr != (intptr_t)AREA_BASE)
        error("failed to map AFL area (shm_id=%s): %s", id_str, strerror(errno));
}

// e9afl code
void __afl_start_forkserver(void)
{
    const unsigned char tmp[4] = {0};
    int child_pid;

    if (write(FORKSRV_FD + 1, tmp, 4) != 4)
        return;

    while (true) {

        unsigned int was_killed;
        if (read(FORKSRV_FD, &was_killed, sizeof(was_killed))
                != sizeof(was_killed))
            error("failed to read from the fork server pipe: %s",
                strerror(errno));

        int status = 0;
        if (was_killed) {
            if (waitpid(child_pid, &status, 0) < 0)
                log("failed to wait for child process: %s", strerror(errno));
        }


        child_pid = fork();
        if (child_pid < 0)
            error("failed to fork process: %s", strerror(errno));


        if (!child_pid) {
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;
        }

        if (write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid))
                != sizeof(child_pid))
            error("failed to write child pid to the fork server pipe: %s",
                strerror(errno));
        if (waitpid(child_pid, &status, 0) < 0)
            log("failed to wait for the child process: %s", strerror(errno));

        if (write(FORKSRV_FD + 1, &status, sizeof(status)) != sizeof(status)) 
            error("failed to write child status to the fork server pipe: %s",
                strerror(errno));
    }
}

void closesockets() {
    int i = 0;
    for(i=0; i<1000; i++) {
            char tmp[50];
            char real[256] = {0};
            sprintf(tmp, "/proc/self/fd/%d", i);
            readlink(tmp, real, sizeof(real));
            if(!strstr(real, "socket")) {
                    continue;
            }
            close(i);
    }
}
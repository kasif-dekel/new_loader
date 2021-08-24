#include "include/utils.h"



void* get_lib_addr(char* libname)
{
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
        //fill the node
        parse_split_line(buf, addr1, addr2, perm, offset, dev, inode, pathname);
        //printf("#%s",buf);
        //printf("%s-%s %s %s %s %s\t%s\n",addr1,addr2,perm,offset,dev,inode,pathname);
        //addr_start & addr_end

        if (strstr(pathname, libname)) {
            sscanf(addr1, "%lx", (long unsigned*)&found_addr);
            goto lbl_cleanup;
        }
    }

lbl_cleanup:
    //close file
    if (file != NULL)
        fclose(file);

    return found_addr;
}

void parse_split_line(
    char* buf, char* addr1, char* addr2,
    char* perm, char* offset, char* device, char* inode,
    char* pathname)
{
    //
    int orig = 0;
    int i = 0;
    //addr1
    while (buf[i] != '-') {
        addr1[i - orig] = buf[i];
        i++;
    }
    addr1[i] = '\0';
    i++;
    //addr2
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        addr2[i - orig] = buf[i];
        i++;
    }
    addr2[i - orig] = '\0';

    //perm
    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        perm[i - orig] = buf[i];
        i++;
    }
    perm[i - orig] = '\0';
    //offset
    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        offset[i - orig] = buf[i];
        i++;
    }
    offset[i - orig] = '\0';
    //dev
    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        device[i - orig] = buf[i];
        i++;
    }
    device[i - orig] = '\0';
    //inode
    while (buf[i] == '\t' || buf[i] == ' ')
        i++;
    orig = i;
    while (buf[i] != '\t' && buf[i] != ' ') {
        inode[i - orig] = buf[i];
        i++;
    }
    inode[i - orig] = '\0';
    //pathname
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


void* lookup_symbol(handle_t* h, const char* symname)
{
    int i, j;
    char* strtab;
    Elf64_Sym* symtab;

    if (h->base_address == NULL) {
        return NULL;
    }

    printf("h->ehdr->e_shnum: %d\n", h->ehdr->e_shnum);
    for (i = 0; i < h->ehdr->e_shnum; i++) {
        if (h->shdr[i].sh_type == SHT_SYMTAB) {
            strtab = (char*)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];

            printf("%p\n", strtab);
            symtab = (Elf64_Sym*)&h->mem[h->shdr[i].sh_offset];

            printf("h->shdr[i].sh_size / sizeof(Elf64_Sym):  %ld\n", h->shdr[i].sh_size / sizeof(Elf64_Sym));
            for (j = 0; j < h->shdr[i].sh_size / sizeof(Elf64_Sym); j++) {
                // printf("%s\n", &strtab[symtab->st_name]);
                if (strcmp(&strtab[symtab->st_name], symname) == 0) {
                    return (void*)(h->base_address + symtab->st_value);
                }
                symtab++;
            }
        }
    }

    return NULL;
}

handle_t* create_module_handle(void* base_address, char* binary_path)
{
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
    // printf("module_handle->ehdr->e_phoff: %lld\n", module_handle->ehdr->e_phoff);
    module_handle->phdr = (Elf64_Phdr*)(module_handle->mem + module_handle->ehdr->e_phoff);
    // printf("module_handle->phdr->p_memsz: %lld\n", module_handle->phdr->p_memsz);
    // printf("module_handle->ehdr->e_shoff: %lld\n", module_handle->ehdr->e_shoff);
    module_handle->shdr = (Elf64_Shdr*)(module_handle->mem + module_handle->ehdr->e_shoff);

    // printf("module_handle->ehdr->e_ident: %s\n", module_handle->ehdr->e_ident);
    //printf("module_handle->shdr->sh_addr: %llx\n", module_handle->shdr->sh_addr);

    if (module_handle->mem[0] != 0x7f) {
        printf("Not an ELF file\n");
        goto lbl_cleanup;
    }

lbl_cleanup:
    return module_handle;
}


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


/* SHM setup. */
void __afl_map_shm(void)
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
void __afl_start_forkserver(void)
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



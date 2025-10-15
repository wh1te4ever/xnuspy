#include <errno.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdbool.h>

#include "../include/xnuspy/xnuspy_ctl.h"

uint64_t kernel_slide = 0;

static void (*_bzero)(void *p, size_t n);
static int (*copyinstr)(const void *uaddr, void *kaddr, size_t len, size_t *done);
static void *(*current_proc)(void);
static void (*kprintf)(const char *, ...);
static void (*proc_name)(int pid, char *buf, int size);
static pid_t (*proc_pid)(void *);
static int (*_strcmp)(const char *s1, const char *s2);
static void *(*unified_kalloc)(size_t sz);
static void (*unified_kfree)(void *ptr);

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;
#define GET(a, b) \
    do { \
        ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, a, b, 0); \
        if(ret){ \
            printf("%s: failed getting %s\n", __func__, #a); \
            return ret; \
        } \
    } while (0)

    GET(BZERO, &_bzero);
    GET(COPYINSTR, &copyinstr);
    GET(CURRENT_PROC, &current_proc);
    GET(KPRINTF, &kprintf);
    GET(PROC_NAME, &proc_name);
    GET(PROC_PID, &proc_pid);
    GET(STRCMP, &_strcmp);
    GET(UNIFIED_KALLOC, &unified_kalloc);
    GET(UNIFIED_KFREE, &unified_kfree);

    return 0;
}

/*
struct kalloc_result
kalloc_ext(
	kalloc_heap_t         kheap, -> void*
	vm_size_t             req_size, -> uint64_t
	zalloc_flags_t        flags, -> uint64_t
	vm_allocation_site_t  *site) -> uint64_t
*/


struct kalloc_result {
	void         *addr;
	vm_size_t     size;
};

static struct kalloc_result (*kalloc_ext_orig)(uint64_t, uint64_t, uint64_t, uint64_t);

static struct kalloc_result kalloc_ext(uint64_t kheap, uint64_t req_size, uint64_t flags, uint64_t site){
    struct kalloc_result kret = kalloc_ext_orig(kheap, req_size, flags, site);
    uint64_t caller = (uint64_t)(__builtin_return_address(0) - kernel_slide);

    if(req_size >= 0x3000) {

        // if(caller == 0xFFFFFFF00715B9F)  //Is it called from ipc_kmsg_copyin_from_user?
        // if((kheap-kernel_slide) == 0xFFFFFFF0070C2D58 && req_size == 0x4000)  //Is KHEAP_DEFAULT?
        // {
        //     // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext caller: 0x%llx\n", (__builtin_return_address(0) - kernel_slide));
        //     kprintf("[XNUSPY_TEST_iOS15] kalloc_ext[KHEAP_DEFAULT] req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);
        // }

        // // if(caller == 0xFFFFFFF007159D80)    //Is called from ipc_kmsg_alloc?
        // if((kheap-kernel_slide) == 0xFFFFFFF0070C3350 && req_size == 0x3fcc)  //Is KHEAP_DATA_BUFFERS?
        // {
        //     // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext caller: 0x%llx\n", (__builtin_return_address(0) - kernel_slide));
        //     kprintf("[XNUSPY_TEST_iOS15] kalloc_ext[KHEAP_DATA_BUFFERS] req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);
        // }


        // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);



        if((kheap-kernel_slide) == 0xFFFFFFF0070C2D58 && req_size >= 0x3000)  //Is KHEAP_DEFAULT?
        {
            // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext caller: 0x%llx\n", (__builtin_return_address(0) - kernel_slide));
            kprintf("[XNUSPY_TEST_iOS15] kalloc_ext[KHEAP_DEFAULT] req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);
        }

        if((kheap-kernel_slide) == 0xFFFFFFF0070C3350 && req_size >= 0x3000)  //Is KHEAP_DATA_BUFFERS?
        {
            // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext caller: 0x%llx\n", (__builtin_return_address(0) - kernel_slide));
            kprintf("[XNUSPY_TEST_iOS15] kalloc_ext[KHEAP_DATA_BUFFERS] req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);
        }


        if((kheap-kernel_slide) == 0xFFFFFFF0070C3828 && req_size >= 0x3000)  //Is KHEAP_KEXT?
        {
            // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext caller: 0x%llx\n", (__builtin_return_address(0) - kernel_slide));
            kprintf("[XNUSPY_TEST_iOS15] kalloc_ext[KHEAP_KEXT] req_size: 0x%llx, kheap = 0x%llx, kret = 0x%llx\n", req_size, kheap-kernel_slide, kret);
        }
    }



    // if(req_size >= 0x4000) {
        // kprintf("[XNUSPY_TEST_iOS15] kalloc_ext req_size: 0x%llx, kret = 0x%llx\n", req_size, kret);
    // }

    return kret;
}

bool install_kernel_hook(void){
    size_t oldlen = sizeof(long);
    int res = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(res == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return false;
    }

    res = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

    if(res != 999){
        printf("xnuspy_ctl isn't present?\n");
        return false;
    }

	res = gather_kernel_offsets();

    if(res){
        printf("something failed: %s\n", strerror(errno));
        return 1;
    }

    res = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE,
            &kernel_slide, 0, 0);
    if(res){
        printf("failed reading kernel slide from xnuspy cache\n");
        return false;
    }
	printf("kernel_slide = 0x%llx\n", kernel_slide);

    /* iPhone 6s, 15.0 */
    uint64_t kalloc_ext_kaddr = 0xFFFFFFF007188808;

    res = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            kalloc_ext_kaddr, kalloc_ext, &kalloc_ext_orig);
	
	printf("XNUSPY_INSTALL_HOOK res = %d\n", res);

    if(res)
        return false;

    return true;
}

int main(int argc, char **argv){

	install_kernel_hook();

	while(1) {};

    return 0;
}
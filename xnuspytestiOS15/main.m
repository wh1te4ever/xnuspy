#include <errno.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

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
kern_return_t
kernel_memory_allocate(
	vm_map_t        map,
	vm_offset_t     *addrp,
	vm_size_t       size,
	vm_offset_t     mask,
	kma_flags_t     flags,
	vm_tag_t        tag)
*/

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

uint64_t (*kfree_orig)(uint64_t, uint64_t);

uint64_t kfree(uint64_t data, uint64_t size){
    // uint64_t caller = (uint64_t)__builtin_return_address(0) - kernel_slide;

	// if(size >= 0x4000) {
		kprintf("[XNUSPY_TEST_iOS15] kfree called, data: 0x%llx, size: 0x%llx\n",data, size);
	// }

    uint64_t kret = kfree_orig(data, size);

	// *(uint64_t*)0x4141414141414141 = 0x4242424242424242;

    /* if(caller == 0xfffffff007fc0f24){ */
    /* XXX iphone se 14.7 below */
    // if(caller == 0xfffffff007658300){
    //     uint64_t osdata_mem = *addrp;

    //     if(size == 0x10000 && g_record_osdata_kaddrs){
    //         g_osdata_kaddrs[g_osdata_kaddrs_idx] = (void *)osdata_mem;
    //         g_osdata_kaddrs_idx++;
    //     }
    // }

    return kret;
}

bool install_kernel_memory_allocate_hook(void){
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

    // /* iPhone 6s, 15.0 */
    uint64_t kfree_kaddr = 0xFFFFFFF007188E94;

    res = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            kfree_kaddr, kfree, &kfree_orig);
	
	printf("XNUSPY_INSTALL_HOOK res = %d\n", res);

    if(res)
        return false;

    return true;
}

int main(int argc, char **argv){

	install_kernel_memory_allocate_hook();

	while(1) {};

//     size_t oldlen = sizeof(long);
//     int ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
//             &oldlen, NULL, 0);

//     if(ret == -1){
//         printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
//                 strerror(errno));
//         return 1;
//     }

//     ret = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

//     if(ret != 999){
//         printf("xnuspy_ctl isn't present?\n");
//         return 1;
//     }

//     ret = gather_kernel_offsets();

//     if(ret){
//         printf("something failed: %s\n", strerror(errno));
//         return 1;
//     }

    /* iPhone 6s 15.1 */
    // ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF0073246D0,
    //         open1, &open1_orig);

    // if(ret){
    //     printf("Could not hook open1: %s\n", strerror(errno));
    //     return 1;
    // }

    // for(;;){
    //     int fd = open(BLOCKED_FILE, O_CREAT);

    //     if(fd == -1)
    //         printf("open failed: %s\n", strerror(errno));
    //     else{
    //         printf("Got valid fd? %d\n", fd);
    //         close(fd);
    //     }

    //     sleep(1);
    // }

    return 0;
}
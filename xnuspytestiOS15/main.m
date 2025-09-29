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

uint64_t (*kalloc_ext_orig)(void *, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t kalloc_ext(void *kheap, uint64_t req_size, uint64_t flags, uint64_t site, uint64_t unk){
    // uint64_t caller = (uint64_t)__builtin_return_address(0) - kernel_slide;

	// *(uint64_t*)0x4141414141414141 = 0x4242424242424242;

    uint64_t kret = kalloc_ext_orig(kheap, req_size, flags, site, unk);

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
    long SYS_xnuspy_ctl;
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

    res = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE,
            &kernel_slide, 0, 0);
    if(res){
        printf("failed reading kernel slide from xnuspy cache\n");
        return false;
    }
	printf("kernel_slide = 0x%llx\n", kernel_slide);

    // /* iPhone 6s, 15.1 */
    uint64_t kalloc_ext_kaddr = 0xFFFFFFF0071886E0;

    res = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK,
            kalloc_ext_kaddr, kalloc_ext, &kalloc_ext_orig);

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
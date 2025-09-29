RP = $(realpath $(shell pwd))

export RP

TARGET_DIRS = loader opdump module klog example

all : $(TARGET_DIRS)

.PHONY: all clean $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

clean:
	find . -name "*.o" -delete;
	rm opdump/opdump;
	rm loader/loader;
	rm klog/klog;
	rm example/kaddr_of_port;
	rm example/kernel_thread;
	rm example/open1_hook;
	rm example/shmem;
	rm example/user_client_monitor;

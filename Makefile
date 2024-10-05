# Makefile for CW-Lite Linux Security Module

# The name of the module
obj-m += sample.o

# Kernel source directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Install the module
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# Remove the module
uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/sample.ko
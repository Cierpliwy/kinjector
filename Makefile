obj-m := kernelinjector.o
kernelinjector-y := kinjector.o injection.o parser.o execute.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd) 

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

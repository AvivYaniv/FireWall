obj-m += firewall.o
firewall-objs := tcp_connection.o connection_table.o log_module.o rules_module.o firewall_module.o fw.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

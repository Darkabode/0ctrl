#
# Makefile for controller
#

include $(POCO_BASE)/build/rules/global

objects = main common stream lzma msgobf payloads

SYSLIBS += -L/usr/local/lib -L/usr/local/lib/mysql -L/usr/lib/mysql -L/usr/mysql/lib/mysql
INCLUDE += -I/usr/local/include/ -I/usr/local/include/mysql/ -I/usr/include/mysql/ -I/usr/mysql/include/mysql
SYSFLAGS += -DTHREADSAFE -DNO_TCL

SYSLIBS += -lmysqlclient

target         = zer0ctrl
target_version = 1
target_libs    = PocoUtil PocoNet PocoData PocoDataMySQL PocoXML PocoJSON PocoFoundation

include $(POCO_BASE)/build/rules/exec

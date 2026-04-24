nvdcli: nvdcli.c json.c json.h sqlite3.o
	cc -o nvdcli -Isqlite-amalgamation-330000 -lsqlite3 $$(curl-config --libs) nvdcli.c json.c

sqlite3.o:
	cc -shared -o sqlite3.o sqlite-amalgamation-3530000/sqlite3.c

all: nvdcli

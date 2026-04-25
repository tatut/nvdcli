nvdcli: nvdcli.c json.c json.h sqlite-amalgamation-3530000/sqlite3.c
	cc -o nvdcli -Isqlite-amalgamation-330000 -lsqlite3 $$(curl-config --libs) nvdcli.c json.c sqlite-amalgamation-3530000/sqlite3.c

all: nvdcli

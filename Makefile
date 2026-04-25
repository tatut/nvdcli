nvdcli: nvdcli.c json.c json.h sqlite-amalgamation-3530000/sqlite3.c
	cc -DSQLITE_ENABLE_FTS5 -o nvdcli -Isqlite-amalgamation-3530000 nvdcli.c json.c sqlite-amalgamation-3530000/sqlite3.c -lm $$(curl-config --libs)


all: nvdcli
clean:
	rm -f nvdcli

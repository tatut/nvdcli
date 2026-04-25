nvdcli: nvdcli.c json.c json.h sqlite-amalgamation-3530000/sqlite3.c
	cc -DSQLITE_ENABLE_FTS5 -o nvdcli -Isqlite-amalgamation-3530000 -lm $$(curl-config --libs) nvdcli.c json.c sqlite-amalgamation-3530000/sqlite3.c


all: nvdcli
clean:
	rm -f nvdcli

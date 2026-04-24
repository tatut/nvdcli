#include <math.h>
#include <stdio.h>
#include "sqlite3.h"
#include <curl/curl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include "json.h"

const char *default_db_file = "nvd.data";

typedef enum cmd {
  USAGE,  // default command if no args given
  SHOW,   // show info about CVE id
  SEARCH, // fts search
  BUILD,  // build the db from scratch
  UPDATE  // find any changes after the latest one, update those
} cmd;

typedef struct args {
  const char *db_file;
  const char *nvd_api_key;
  cmd command;
  char *args[16]; // command args (first NULL means no more args)
} args;


/* Read arguments, note that any memory allocated for args is not freed.
 * Arguments live for the duration of the program.
 */
bool read_args(int argc, char **argv, args *a) {
  a->db_file = default_db_file;
  a->command = USAGE;
  a->nvd_api_key = getenv("NVD_API_KEY");
  bool cmd = false;
  int cmd_args = 0;
  while(argc) {
    printf(" argc: %d\n", argc);
    if(strcmp(argv[0], "--db-file")==0) {
      struct stat db_stat;
      int s;
      if(argc < 2) {
        fprintf(stderr, "error: --db-file requires a file name/path\n");
        return false;
      }
      a->db_file = argv[1];
      s = stat(a->db_file, &db_stat);
      if (s != 0) {
        if(errno != ENOENT) {
          fprintf(stderr, "error: Can't stat db file: %s [%s]\n", a->db_file, strerror(errno));
          return false;
        } else {
          fprintf(stderr, "Database file %s does not exist and will be created.\n", a->db_file);
        }
      } else if (db_stat.st_mode & S_IFDIR) {
        fprintf(stderr, "error: Path \"%s\" is a directory!\n", a->db_file);
        return false;
      }
      argc -= 2;
      argv += 2;
    } else if (strcmp(argv[0], "--nvd-api-key")==0) {
      if (argc < 2) {
        fprintf(stderr, "error: --nvd-api-key requires a parameter\n");
        return false;
      }
      a->nvd_api_key = argv[1];
      argc -= 2;
      argv += 2;
    } else if (strncmp(argv[0], "--", 2) == 0) {
      fprintf(stderr, "error: unrecognized parameter %s\n", argv[0]);
      return false;
    } else {
      if (!cmd) {
        if (strcmp(argv[0], "show") == 0) {
          a->command = SHOW;
        } else if (strcmp(argv[0], "search") == 0) {
          a->command = SEARCH;
        } else if (strcmp(argv[0], "build") == 0) {
          a->command = BUILD;
        } else if (strcmp(argv[0], "update") == 0) {
          a->command = UPDATE;
        } else {
          fprintf(stderr, "Unrecognized command: %s\n", argv[0]);
          return false;
        }
        cmd = true;
      } else {
        if (cmd_args > 15) {
          fprintf(stderr, "Too many arguments!\n");
          return false;
        }
        a->args[cmd_args++] = argv[0];
      }
      argv += 1;
      argc -= 1;
    }
  }
  return true;
}

bool open_db(args *a, sqlite3 **db) {
  int res = sqlite3_open(a->db_file, db);
  if(res != SQLITE_OK) {
    fprintf(stderr, "Could not open SQLite database: %s [%s]\n", a->db_file,
            sqlite3_errstr(res));
    return false;
  }
  return true;
}

typedef struct read_data {
  char *buffer;
  size_t buffer_capacity;
  size_t buffer_pos;
} read_data;

typedef struct insert_ctx {
  sqlite3 *db;
  bool success;
  char *error;
} insert_ctx;

/* JSON object data as is (not parsed, just pointer and len) */
typedef struct jobj {
  char id[64]; //extract id field
  char *data;
  size_t len;
} jobj;

size_t read_cve_result(void *buffer, size_t size, size_t nmemb, read_data *c) {
  //printf("Got %zu nmemb %zu data\n", size, nmemb);
  size_t sz = size*nmemb;
  if (c->buffer_pos + sz + 1 > c->buffer_capacity) {
    size_t new_capacity = c->buffer_pos + sz + 4096;
    c->buffer = realloc(c->buffer, new_capacity);
    if (!c->buffer) {
      fprintf(stderr, "Out of memory reading result! wanted: %zu bytes\n",
              new_capacity);
      return 0;
    }
    c->buffer_capacity = new_capacity;
  }
  memcpy(&c->buffer[c->buffer_pos], buffer, sz);
  c->buffer_pos += sz;
  c->buffer[c->buffer_pos] = 0; // NUL terminate
  return sz;
}

bool json_vuln_object(char **at, jobj *obj) {
  json_skipws(at);
  obj->data = *at;
  // printf("vuln object: %.*s\n", 100, obj->data);
  char *befo = *at;
  if (!json_skip(at)) {
    printf("FAILED TO SKIP: %s\n", befo);
    return false;
  }
  obj->len = *at - obj->data;

  // extract the key
  char *od = obj->data;
  char **o = &od;
  json_object(o, {
    json_field("id", json_string_64, obj->id);
    json_ignore_unknown_fields();
    });

  return true;
}
bool json_insert_vuln(char **at, insert_ctx *ic) {
  json_skipws(at);
  json_expect_consume(at, '[');
  json_skipws(at);
  while (**at == '{') {
    jobj v;
    json_object(at, {
        json_field("cve", json_vuln_object, &v);
      });
    json_skipws(at);
    /* We got a vuln, we need to extract the id from it,
       PENDING: we could empty it from the source so the JSONB would
       be smaller, along with some other fields as well...
     */
    sqlite3_stmt *stmt;
    int res =
        sqlite3_prepare(ic->db, "INSERT INTO cve (id, data) VALUES (?, ?)", -1,
                        &stmt, NULL);
    if (res != SQLITE_OK) {
      fprintf(stderr, "Failed to prepare SQLite insert: %s\n",
              sqlite3_errstr(res));
      return false;
    }
    sqlite3_bind_text(stmt, 1, v.id, -1, NULL);
    sqlite3_bind_text(stmt, 2, v.data, v.len, NULL);

    res = sqlite3_step(stmt);
    if (res != SQLITE_DONE) {
      fprintf(stderr, "Failed to insert SQLIte vuln: %s\n",
              sqlite3_errstr(res));
      sqlite3_finalize(stmt);
      return false;
    }
    sqlite3_finalize(stmt);

    //printf("GOT VULN id: %s  has len %zu : %.*s\n", v.id, v.len, 10, v.data);
    if (**at == ',')
      json_expect_consume(at, ',');
    if (**at == ']') {
      json_expect_consume(at, ']');
      break;
    }
  }
  return true;
}

/* build database, initialize the table, query all NVDs */
bool build_db(args *a, sqlite3 *db) {
  sqlite3_stmt *stmt;
  int res;
  char url[512];
  CURL *curl;
  bool success = true;

  res = sqlite3_prepare(db,
                        "CREATE TABLE IF NOT EXISTS cve ("
                        "id TEXT PRIMARY KEY, "
                        "data JSONB)",
                        -1, &stmt, NULL);
  if (res != SQLITE_OK) {
    fprintf(stderr, "error: %s\n", sqlite3_errstr(res));
    success = false;
    goto done;
  }
  res = sqlite3_step(stmt);
  if (res != SQLITE_DONE) {
    fprintf(stderr, "error: %s\n", sqlite3_errstr(res));
    success = false;
    goto done;
  }
  res = sqlite3_finalize(stmt);
  if (res != SQLITE_OK) {
    fprintf(stderr, "error: %s\n", sqlite3_errstr(res));
    success = false;
    goto done;
  }

  /* db ready, let's start pulling NVDs */
https: // services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=0
  curl = curl_easy_init();
  if (!curl) {
    fprintf(stderr, "Couldn't init curl :'(\n");
    success = false;
    goto done;
  }

  int loaded = 0, results_per_page;
  int total_results = -1; // not known until 1st result
  read_data rd = {.buffer = malloc(1 << 20), .buffer_capacity = 1 << 20};
  if (!rd.buffer) {
    fprintf(stderr, "Can't allocate buffer\n");
    success = false;
    goto done;
  }
  insert_ctx ic = {.db = db};
  printf("Start fetching.\n");
  while (total_results == -1 || loaded < total_results) {
    char api_key[256];
    char error[CURL_ERROR_SIZE];
    snprintf(api_key, 256, "apiKey: %s", a->nvd_api_key);
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, api_key);

    snprintf(url, 512,
             "https://services.nvd.nist.gov/rest/json/cves/2.0/"
             "?resultsPerPage=1000&startIndex=%d",
             loaded);
    rd.buffer_pos = 0;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, read_cve_result);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rd);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    CURLcode result = curl_easy_perform(curl);
    if (result != CURLE_OK) {
      fprintf(stderr, "Fetch failed: %s\n", error);
      // FIXME: wait and try again
      goto done;
    }

    /* JSON was read, start the parsing */
    //printf("JSON\n%.*s\n---------\n", (int)rd.buffer_capacity, rd.buffer);
    char *json = rd.buffer;
    char **at = &json;
    char version[64];
    json_object(at, {
        json_field("resultsPerPage", json_int, &results_per_page);
        json_field("totalResults", json_int, &total_results);
        json_field("version", json_string_64, version);
        json_field("vulnerabilities", json_insert_vuln, &ic);
        json_ignore_unknown_fields();
      });

    loaded += results_per_page;
    // print progress bar
    float pct = (loaded * 100.0 / total_results);
    int p = lroundf(pct) / 4;
    printf("\r");
    for (int i = 1; i < 26; i++) {
      printf("%s", (p >= i ? "█" : "░"));
    }
    printf(" %.1f%% (%d/%d)", pct, loaded, total_results);
    fflush(stdout);
    sleep(1); // is this enough?
    curl_slist_free_all(list);
    curl_easy_reset(curl);

  }

done:
  if (curl)
    curl_easy_cleanup(curl);
  if (rd.buffer)
    free(rd.buffer);
  return success;
}

bool show(args *a, sqlite3 *db) {
  printf("here it is \n");
  return true;
}
int main(int argc, char **argv) {
  args args = {0};
  if (!read_args(argc - 1, argv + 1, &args))
    return 1;
  sqlite3 *db;
  if (!open_db(&args, &db))
    return 1;

  printf("command is %d\n", args.command);
  switch(args.command) {
  case USAGE:
    printf("Usage: nvdcli [options] command [...command args...]\n"
           "Options:\n"
           " --db-file <file>          Path to database file (defaults to "
           "nvd.data in cwd)\n"
           " --nvd-api-key <api key>   NVD API key (defaults to NVD_API_KEY "
           "env variable)\n"
           "\n"
           "Commands:\n"
           " build                     Initialize database and fetch all NVDs\n"
           " update                    Update NVDs that have changed since "
           "last update (or build) date\n"
           " show <CVE ID>             Show information on the given CVE\n"
           " search <keywords...>      Search CVE database for hits for the "
           "given keywords\n\n");
    break;
  case BUILD:
    if (!build_db(&args, db))
      return 1;
    break;
  case SHOW:
    if (!show(&args, db))
      return 1;
    break;
  default:
    fprintf(stderr, "Not yet implemented: %d\n", args.command);
  }

  sqlite3_close(db);
  return 0;
}

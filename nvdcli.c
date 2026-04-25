#include <ctype.h>
#include <math.h>
#include <stdint.h>
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
  SHOW,   // show human readable info about CVE id
  GET,    // synonym for show, but sets output to raw json
  SEARCH, // simple fts search
  QUERY,  // allow queries like with multiple values `severity:HIGH match:jackson*`
  BUILD,  // build the db from scratch
  UPDATE  // find any changes after the latest one, update those
} cmd;

typedef enum output {
  ID,      // output only CVE ids, one per line
  SHORT,   // short human readable output (default)
  VERBOSE, // verbose human readable output
  JSON     // full CVE JSON data (for tools)
} output;

typedef struct args {
  const char *db_file;
  const char *nvd_api_key;
  cmd command;
  output fmt;
  bool fmt_set; // is fmt set explicitly
  char *args[32]; // command args (first NULL means no more args)
} args;


/* Read arguments, note that any memory allocated for args is not freed.
 * Arguments live for the duration of the program.
 */
bool read_args(int argc, char **argv, args *a) {
  a->db_file = default_db_file;
  a->command = USAGE;
  a->nvd_api_key = getenv("NVD_API_KEY");
  a->fmt = SHORT;
  a->fmt_set = false;
  bool cmd = false;
  int cmd_args = 0;
  while(argc) {
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
    } else if (strcmp(argv[0], "--output") == 0) {
      if (argc < 2) {
        fprintf(stderr, "error: --output requires a parameter\n");
        return false;
      }
      if (strcmp(argv[1], "id") == 0) {
        a->fmt = ID;
      } else if (strcmp(argv[1], "short") == 0) {
        a->fmt = SHORT;
      } else if (strcmp(argv[1], "verbose") == 0) {
        a->fmt = VERBOSE;
      } else if (strcmp(argv[1], "json") == 0) {
        a->fmt = JSON;
      } else {
        fprintf(stderr,
                "error: '%s' is not a valid format (use: id, short, verbose or "
                "json)\n",
                argv[1]);
        return false;
      }
      a->fmt_set = true;
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
        } else if (strcmp(argv[0], "get") == 0) {
          a->command = GET;
        } else if (strcmp(argv[0], "query") == 0 || strcmp(argv[0], "q") == 0) {
          a->command = QUERY;
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

#define SQ_CHECK(res)                                                          \
  do {                                                                         \
    if ((res) != SQLITE_OK) {                                                  \
      fprintf(stderr, "[%s:%d] SQLite error: %s\n", __FILE__, __LINE__, sqlite3_errstr((res))); \
      success = false;                                                         \
      goto done;                                                               \
    }                                                                          \
  } while (false)


bool sq_exec(sqlite3 *db, const char *sql) {
  sqlite3_stmt *stmt = NULL;
  int res;
  bool success = true;

  res = sqlite3_prepare(db, sql, -1, &stmt, NULL);
  SQ_CHECK(res);
  res = sqlite3_step(stmt);
  if (res != SQLITE_DONE) {
    fprintf(stderr, "Unexpected DDL statement return: %s\nDDL: %s\n",
            sqlite3_errstr(res), sql);
    success = false;
  }
 done:
  if (stmt)
    sqlite3_finalize(stmt);
  return success;
}
/* build database, initialize the table, query all NVDs */
bool build_db(args *a, sqlite3 *db) {
  sqlite3_stmt *stmt;
  int res;
  char url[512];
  CURL *curl;
  bool success = true;

  if (!sq_exec(db, "CREATE TABLE IF NOT EXISTS cve ("
                   "id TEXT PRIMARY KEY, "
                   "data JSONB)"))
    return false;
  if (!sq_exec(db,
               "CREATE VIRTUAL TABLE cve_search USING fts5 (cve, description)"))
    return false;

  SQ_CHECK(res);
  res = sqlite3_step(stmt);
  if (res != SQLITE_DONE) {
    fprintf(stderr, "error: %s\n", sqlite3_errstr(res));
    success = false;
    goto done;
  }
  res = sqlite3_finalize(stmt);
  SQ_CHECK(res);

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
  printf("Fetch done, generating FTS5 search index.");
  if (!sq_exec(db, "INSERT INTO cve_search (cve, description) SELECT id AS "
               "cve, data->>'$.descriptions[0].value' FROM cve")) {
    success = false;
  }

done:
  if (curl)
    curl_easy_cleanup(curl);
  if (rd.buffer)
    free(rd.buffer);
  return success;
}

bool display(args *a, sqlite3 *db, char *id, char *cve_id,
             char *cve_description);

bool show(args *a, sqlite3 *db) {
  int i = 0;
  while (a->args[i] != NULL) {
    if (!display(a, db, a->args[i], NULL, NULL))
      return false;
    i++;
  }
  return true;
}

#define HL_START_TAG "<<HL"
#define HL_END_TAG "HL>>"

void print_hl(char *in, char *hl_start, char *hl_end, int max_len) {
  char *at = in;
  int len = strlen(in);
  if (max_len < len)
    len = max_len;
  bool in_hl = false;
  while (len > 0) {
    if (*at == '<') {
      // printf("at: %.*s, start? %s\n", 10, at,
      //     strncmp(at, HL_START_TAG, 4)==0 ? "true" : "false");

    }
    if (strncmp(at, HL_START_TAG, 4) == 0) {
      printf("%s", hl_start);
      at += 4;
      len -= 4;
      in_hl = true;
      continue;
    } else if (strncmp(at, HL_END_TAG, 4) == 0) {
      printf("%s", hl_end);
      at += 4;
      len -= 4;
      in_hl = false;
      continue;
    }
    if(isprint(*at)) {
      printf("%c", *at);
    } else {
      printf("[%d]", *at);
    }
    at++;
    len--;
  }
  if (in_hl)
    printf("%s", hl_end);
}

#define HL_START "\e[1;92m"
#define HL_END "\e[0m"
#define TRUNC "\e[44m[...]\e[0m"

const char *display_query[] = {
    // just the id
    [ID] = "SELECT id FROM cve WHERE id=?",
    // publication date, severity and description
    [SHORT] = "SELECT data->>'$.published',"
              "       data->>'$.metrics.cvssMetricV2[0].baseSeverity',"
              "       data->>'$.descriptions[0].value'"
              "  FROM cve WHERE id=?",
    // recursive tree walk of the json, so we can format all of it
    [VERBOSE] = "SELECT key, value, type, t.id, parent FROM cve, "
                "json_tree(data) t WHERE cve.id=?",

    // get the data as JSON
    [JSON] = "SELECT data FROM cve WHERE id=?"};

void indent(int level) {
  for (int i = 0; i < level; i++)
    putchar(' ');
}

/* recursively display the json tree,
 * returns true if the fetched row is still unhandled,
 * this is for when returning from nested calls
 */
bool display_verbose(int level, int expected_parent, sqlite3_stmt *stmt,
                     bool in_array) {
  int res, id, parent;
  char *key, *type, *id_str, *parent_str;

 start:
  key = (char*) sqlite3_column_text(stmt, 0);
  type = (char*) sqlite3_column_text(stmt, 2);
  id_str = (char*) sqlite3_column_text(stmt, 3);
  parent_str = (char*) sqlite3_column_text(stmt, 4);

  id = id_str ? atoi(id_str) : -1;
   parent = parent_str ? atoi(parent_str) : -1;

  if(expected_parent != parent) return true; // done with

  if(key != NULL) {
    indent(level);
    printf("\e[0;36m%s\e[0m: ", key);
  }

  if (strcmp(type, "array") == 0) {
    // output the key, then recurse to children
    res = sqlite3_step(stmt);
    if (res == SQLITE_DONE)
      return false;
    printf("\n");
    if(display_verbose(level + 2, id, stmt, true)) goto start;
  } else if (strcmp(type, "object") == 0) {
    res = sqlite3_step(stmt);
    if (res == SQLITE_DONE)
      return false;
    printf("\n");
    bool unhandled = display_verbose(level + 2, id, stmt, false);
    if(unhandled) goto start;
  } else {
    char *type_color = "\e[0;37m";
    char *value = (char*) sqlite3_column_text(stmt, 1);
    if (strcmp(type, "text") == 0) {
      type_color = "\e[0;34m";
    } else if (strcmp(type, "real") == 0) {
      type_color = "\e[0;35m";
    } else if (strcmp(type, "false") == 0) {
      type_color = "\e[0;31m";
      value = "false";
    } else if (strcmp(type, "true") == 0) {
      type_color = "\e[0;32m";
      value = "true";
    }
    printf("%s%s\e[0m\n", type_color, value);
    res = sqlite3_step(stmt);
    if (res == SQLITE_DONE)
      return false;
    goto start;
  }

  return false; // this row was handled

}
/* Generic display, fetches data by id.
 * If cve_id, cve_description are non-NULL (from search with possible highlight)
 * those are used in place of the fetched ones.
 */
bool display(args *a, sqlite3 *db, char *id, char *cve_id, char *cve_description) {
  static sqlite3_stmt *stmt = NULL; // reused on successive calls
  int ret;

  bool success = true;
  if (stmt == NULL) {
    ret =
        sqlite3_prepare(db, display_query[a->fmt], -1, &stmt, NULL);
    SQ_CHECK(ret);
  }
  ret = sqlite3_bind_text(stmt, 1, id, -1, NULL);
  SQ_CHECK(ret);
  ret = sqlite3_step(stmt);
  if (ret != SQLITE_ROW) {
    fprintf(stderr, "No such CVE: %s\n", id);
    return false;
  }
  switch (a->fmt) {
  case ID:
    printf("%s\n", id);
    break;
  case SHORT: {
    if (cve_id)
      print_hl(cve_id, HL_START, HL_END, 256);
    else
      printf("%s", id);
    printf("\n published: %s\n severity: %s\n", sqlite3_column_text(stmt, 0),
           sqlite3_column_text(stmt, 1));
    char *desc = cve_description;
    if (!desc) {
      desc = (char*)sqlite3_column_text(stmt, 2);
    }
    size_t len = strlen(desc);
    char *hl = strstr(desc, HL_START_TAG);
    if (hl - desc > 90) {
      printf(TRUNC);
      print_hl(hl - 10, HL_START, HL_END, 100);
    } else {
      print_hl(desc, HL_START, HL_END, 100);
    }
    if (len > 100)
      printf(TRUNC);
    printf("\n");
    break;
  }
  case VERBOSE:
    display_verbose(0, -1, stmt, false);
    break;
  case JSON:
    printf("%s", sqlite3_column_text(stmt, 0));
    break;
  }

done:
  if (stmt) {
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
  }
  return success;
}

#define MAX_SQL 2048
bool query(args *a, sqlite3 *db) {
  char sql[MAX_SQL];
  char *query_args[32];
  bool query_arg_number[32] = {0};
  size_t len = 0;
  int res;
  bool success = true;
  sqlite3_stmt *stmt = NULL;
  len += snprintf(&sql[len], MAX_SQL - len, "SELECT id FROM cve WHERE ");
  int i = 0;
  while (a->args[i] != NULL) {
    char *arg = a->args[i];
    if (strncmp(arg, "sev:", 4) == 0) {
      len +=
          snprintf(&sql[len], MAX_SQL - len,
                   " %s data->>'$.metrics.cvssMetricV2[0].baseSeverity' = ?%d",
                   i ? " AND " : "", (i + 1));
      query_args[i] = arg + 4;
    } else if (strncmp(arg, "score:", 6) == 0) {
      arg += 6;
      char *op;
      if (*arg == '<') {
        op = " < ";
        arg++;
      } else if (*arg == '>') {
        op = " > ";
        arg++;
      } else {
        op = " = ";
      }
      len +=
        snprintf(&sql[len], MAX_SQL - len,
                 " %s data->>'$.metrics.cvssMetricV2[0].impactScore' %s ?%d",
                 i ? " AND " : "", op, (i + 1));
      query_args[i] = arg;
      query_arg_number[i] = true;
    } else if (strncmp(arg, "match:", 6) == 0) {
      arg += 6;
      len += snprintf(&sql[len], MAX_SQL - len,
                      " %s (id IN (SELECT cve FROM cve_search WHERE (cve MATCH ?%d) OR (description MATCH ?%d)))",
                      i ? " AND " : "", i+1, i+1);
      query_args[i] = arg;
    }

    i++;
  }

  //printf("SQL: %s\n", sql);
  res = sqlite3_prepare(db, sql, -1, &stmt, NULL);
  SQ_CHECK(res);
  int argc = i;
  for (i = 0; i < argc; i++) {
    if (query_arg_number[i]) {
      double d = atof(query_args[i]);
      res = sqlite3_bind_double(stmt, i+1, d);
    } else {
      res = sqlite3_bind_text(stmt, i + 1, query_args[i], -1, NULL);
    }
    SQ_CHECK(res);
  }
  res = sqlite3_step(stmt);
  int results = 0;
  while (res == SQLITE_ROW) {
    results++;
    char *id = (char *)sqlite3_column_text(stmt, 0);
    display(a, db, id, NULL, NULL);
    res = sqlite3_step(stmt);
  }
  if (a->fmt != JSON && a->fmt != ID) {
    // if we are generating human readable output, show result count
    if (!results) {
      printf("No results found.\n");
    } else if (results == 1) {
      printf("1 result found.\n");
    } else {
      printf("%d results found.\n", results);
    }
  }
  if (res != SQLITE_DONE) {
    fprintf(stderr, "Unexpected SQLite status: %s\n", sqlite3_errstr(res));
    success = false;
  }

done:
  if(stmt) sqlite3_finalize(stmt);
  return success;
}

const char *search_query =
    "SELECT cve, highlight(cve_search, 0, '<<HL', 'HL>>'),"
    "       highlight(cve_search, 1, '<<HL','HL>>')"
    "  FROM cve_search"
    " WHERE (cve MATCH ?1)"
    "    OR (description MATCH ?1)"
    " ORDER BY rank";

bool search(args *a, sqlite3 *db) {
  bool success = true;
  int res, i = 0;
  sqlite3_stmt *stmt = NULL;
  res = sqlite3_prepare(db, search_query, -1, &stmt, NULL);
  SQ_CHECK(res);
  while (a->args[i] != NULL) {
    res = sqlite3_bind_text(stmt, 1, a->args[i], -1, NULL);
    SQ_CHECK(res);
    res = sqlite3_step(stmt);
    while (res == SQLITE_ROW) {
      char *raw_id = (char *)sqlite3_column_text(stmt, 0);
      char *id = (char *)sqlite3_column_text(stmt, 1);
      char *desc = (char *)sqlite3_column_text(stmt, 2);
      display(a, db, raw_id, id, desc);
      res = sqlite3_step(stmt);
    }
    if (res != SQLITE_DONE) {
      fprintf(stderr, "Unexpected sqlite status: %s\n", sqlite3_errstr(res));
      success = false;
      goto done;
    }
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    i++;
  }

done:
  if(stmt) sqlite3_finalize(stmt);
  return success;
}

const char *usage =
    "Usage: nvdcli [options] command [...command args...]\n"
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
    " get <CVE ID>              get raw CVE JSON\n"
    " search <keywords...>      Search CVE database for hits for the "
    "given keywords\n"
    " q <filters...>            Search by filters (see below)\n\n";

int main(int argc, char **argv) {
  int ret = 0;
  args args = {0};
  if (!read_args(argc - 1, argv + 1, &args))
    return 1;
  sqlite3 *db;
  if (!open_db(&args, &db))
    return 1;

  switch(args.command) {
  case USAGE:
    printf("%s",usage);
    break;
  case BUILD:
    if (!build_db(&args, db))
      ret = 1;
    break;
  case GET:
    if(!args.fmt_set)
      args.fmt = JSON;
    //fallthrough
  case SHOW:
    if (!show(&args, db))
      ret = 1;
    break;
  case SEARCH:
    if (!search(&args, db))
      ret = 1;
    break;
  case QUERY:
    if (!query(&args, db))
      ret = 1;
    break;
  default:
    fprintf(stderr, "Not yet implemented: %d\n", args.command);
  }

  sqlite3_close(db);
  return ret;
}

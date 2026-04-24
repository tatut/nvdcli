#ifndef JSON_H
#define JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* customize json_panic behaviour */
#ifndef json_panic

#define VA_ARGS(...) , ##__VA_ARGS__
#define json_panic(fmt, ...) \
  fprintf(stderr, "[ERROR] " fmt "\n" VA_ARGS(__VA_ARGS__)); return false;

#endif

bool json_expect(char **at, char CH);
bool json_expect_consume(char **at, char CH);
char json_at(char **at);

bool json_int(char **at, int *value);
bool json_u16(char **at, uint16_t *value);
bool json_u8(char **at, uint8_t *value);
bool json_float(char **at, float *value);
bool json_bool(char **at, bool *value);

void json_skipws(char **at);

/* Read string (of max length n) to given value.
 */
bool json_string(char **at, size_t n, char *value);

/* Read string in JSON, modifies input. Returns a freshly
 * allocated copy of it.
 */
bool json_string_dup(char **at, char **value);

/* Read string and return sub pointer to json.
 * Modifies the end of the string to be '\0'.
 */
bool json_string_ptr(char **at, char **value);

/* Read string of max len 64. */
bool json_string_64(char **at, char *value);
/* Read string of max len 512 */
bool json_string_512(char **at, char *value);

/* skip any JSON value */
bool json_skip(char **pos);

#define json_field(name, parser, to)                                    \
  if (strcmp(name, _json_field) == 0) {                                 \
    if (!parser(_json_obj, to)) {                                       \
      json_panic("Failed to parse field: %s", name);                         \
    }                                                                   \
    continue;                                                           \
  }

#define json_ignore_unknown_fields() if(!json_skip(_json_obj)) { json_panic("Failed to skip JSON value."); } else { continue; }

#define json_object(in, body)                                           \
  char **_json_obj = in;                                                \
  char _json_field[128];                                                \
  bool _json_first = true;                                              \
  if(!json_expect_consume(_json_obj, '{')) return false; \
  while(json_at(_json_obj) != '}') {                                    \
    if(!_json_first) json_expect_consume(_json_obj, ',');               \
    _json_first = false;                                                \
    json_string(_json_obj, 128, _json_field); \
    json_expect_consume(_json_obj, ':');                                \
    body                                                                \
      json_panic("Unhandled JSON field: %s", _json_field);                   \
      }                                                                 \
  json_expect_consume(_json_obj, '}');                                  \
  in = _json_obj;

#define json_array(in, to, type, parser)                                       \
  char **_json_arr = in;                                                        \
  bool _json_first = true;                                                     \
  json_expect_consume(_json_arr, '[');                                         \
  while (json_at(_json_arr) != ']') {                                          \
    if (!_json_first)                                                          \
      json_expect_consume(_json_arr, ',');                                     \
    _json_first = false;                                                       \
    type _json_arr_val;                                                        \
    if (!parser(_json_arr, &_json_arr_val))                                    \
      json_panic("Can't parse array value of type: %s", #type);                  \
    arr_append(to, _json_arr_val);                                             \
  }                                                                            \
  json_expect_consume(_json_arr, ']');                                         \
  in = _json_arr;






#endif

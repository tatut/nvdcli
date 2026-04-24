/* Immediate mode JSON parsing tools.
 *
 *
 * Parsing may modify the JSON input char* to avoid allocating extra
 * memory.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "json.h"

static void skipws(char **at) {
  char c = **at;
  while(c == ' ' || c == '\t' || c == '\n' || c == '\r') {
    *at = *at + 1;
    c = **at;
  }
}

static bool is_alpha(char ch) {
  return (ch >= 'a' && ch <= 'z') ||
    (ch >= 'A' && ch <= 'Z');
}

static bool is_digit(char ch) { return ch >= '0' && ch <= '9'; }

static bool is_alphanumeric(char ch) { return is_alpha(ch) || is_digit(ch); }

static bool looking_at(char *at, char *word) {
  size_t c = 0;
  while(*word != 0) {
    if(*at == 0) return false;
    if(*at != *word) return false;
    at++;
    word++;
    c++;
  }
  return true;
}
static bool looking_at_then(char *at, char *word, char **next) {
  if(looking_at(at, word)) {
    *next = at + strlen(word);
    return true;
  }
  return false;
}

bool json_expect(char **at, char ch) {
  skipws(at);
  return **at == ch;
}

bool json_expect_consume(char **at, char ch) {
  skipws(at);
  if(**at != ch) return false;
  *at = *at + 1;
  return true;
}

char json_at(char **at) {
  skipws(at);
  return **at;
}

bool json_int(char **pos, int *value) {
  skipws(pos);
  char *at = *pos;
  if(!is_digit(*at) && *at != '-') return false;
  int s = 1;

  if(*at == '-') {
    s = -1;
    at++;
  }
  int num = 0;
  while(is_digit(*at)) {
    num *= 10;
    num += *at - '0';
    at++;
  }
  *value = num;
  *pos = at;
  return true;
}

bool json_u16(char **pos, uint16_t *value) {
  int v;
  if(!json_int(pos, &v)) return false;
  if(v <= UINT16_MAX) {
    *value = (uint16_t) v;
    return true;
  }
  return false;
}

bool json_u8(char **pos, uint8_t *value) {
  int v;
  if(!json_int(pos, &v)) return false;
  if(v <= UINT8_MAX) {
    *value = (uint8_t) v;
    return true;
  }
  return false;
}


bool json_float(char **pos, float *value) {
  int intval;
  if(!json_int(pos, &intval)) return false;
  char *at = *pos;
  if(*at == '.') {
    at++;
    // fraction
    double fr = 1;
    double frac = 0;
    while(is_digit(*at)) {
      fr *= 10;
      frac = 10*frac + (*at - '0');
      at++;
    }
    *pos = at;
    float f = intval >= 0 ? 1.0 : -1.0;
    *value = (float) intval + (f * frac/fr);
  } else {
    // integer part only
    *value = (float) intval;
  }
  return true;
}

static int hex(char ch) {
  if(ch >= '0' && ch <= '9') return ch - '0';
  if(ch >= 'A' && ch <= 'F') return ch - ('A' - 10);
  if(ch >= 'a' && ch <= 'f') return ch - ('a' - 10);
  return -1;
}

typedef struct {
  bool success;
  char *start;
  size_t len;
  char *after;
} Str;

static Str parse_string(char *at) {
  char *r, *w;
  // Naive first attempt, just take bytes until '"'
  char *end = at+1;
  while(*end != '"') {
    if(*end == '\\') goto handle_escape;
    end++;
  }
  return (Str) { true, at, end-at, end+1 };

 handle_escape:
  /* handle escapes, mutates input char*, keep track of read and write
   * pointers.
   */
  r = end;
  w = end;
  while(*r != '"') {
    if(*r == '\\') {
      r++;
      switch(*r) {
      case '"': r++; *w = '"'; w++; break;
      case 't': r++; *w = '\t'; w++; break;
      case 'n': r++; *w = '\n'; w++; break;
      case '\\':r++; *w = '\\'; w++; break;
      case '/': r++; *w = '/'; w++; break;
      case 'b': r++; *w = '\b'; w++; break;
      case 'f': r++; *w = '\f'; w++; break;
      case 'u': {
        char hex[5] = { *(r+1), *(r+2), *(r+3), *(r+4), 0 };
        char *_end;
        long codepoint = strtol(hex, &_end, 16);

        if(codepoint <= 127) {
          // single utf-8 byte
          *w = codepoint;
          w++;
        } else if(codepoint <= 2047) {
          // 2 bytes
          *w = 0b11000000 + (0b00011111 & (codepoint>>6));
          w++;
          *w = 0b10000000 + (0b00111111 & codepoint);
        } else if(codepoint <= 65535) {
          *w = 0b11100000 + (0b00001111 & (codepoint>>12));
          w++;
          *w = 0b10000000 + (0b00111111 & (codepoint>>6));
          w++;
          *w = 0b10000000 + (0b00111111 & codepoint);
          w++;
        } else if(codepoint <= 1114111) {
          *w = 0b11110000 + (0b00000111 & (codepoint>>18));
          w++;
          *w = 0b10000000 + (0b00111111 & (codepoint>>12));
          w++;
          *w = 0b10000000 + (0b00111111 & (codepoint>>6));
          w++;
          *w = 0b10000000 + (0b00111111 & codepoint);
          w++;
        }
        r += 5;

      }
      }
    } else {
      *w = *r;
      w++; r++;
    }
  }
  return (Str) { true, at, w-at, r+1 };

 fail:
  return (Str) { false, 0, 0, 0 };

}

// read simple '"' delimited string of maxlen
bool json_string(char **pos, size_t maxlen, char *value) {
  if(!json_expect_consume(pos, '"')) return false;
  char *at = *pos;

  Str s = parse_string(at);
  if(s.success) {
    if(s.len < maxlen-1) {
      memcpy(value, s.start, s.len);
      value[s.len] = 0;
      *pos = s.after;
      return true;
    } else {
      json_panic("Not enough space for string: %zu < %zu", maxlen, s.len);
    }
  }
  return false;
}

bool json_string_64(char **pos, char *value) {
  return json_string(pos, 64, value);
}
bool json_string_512(char **pos, char *value) {
  return json_string(pos, 512, value);
}

bool json_string_ptr(char **pos, char **value) {
  if(!json_expect_consume(pos, '"')) return false;
  char *at = *pos;

  Str s = parse_string(at);
  if(s.success) {
    *(s.start + s.len) = 0;
    *value = s.start;
    *pos = s.start + s.len + 1;
    return true;
  }
  return false;
}

bool json_string_dup(char **pos, char **value) {
  char *ptr;
  if (!json_string_ptr(pos, &ptr))
    return false;
  *value = strdup(ptr);
  if(!*value) return false;
  return true;
}

void json_skipws(char **pos) { skipws(pos); }

static bool json_skip_string(char **pos) {
  char *start = *pos;
  json_expect_consume(pos, '"');
  while (1) {
    if (**pos == '\\') {
      *pos += 1;
      switch (**pos) {
      case '"': case 't': case 'n': case 'r':
      case '\\': case '/': case 'b':
      case 'f':
        *pos += 1; // skip simple 1 char escapes
        break;

      case 'u':
        // skip 4 digit unicode escape, with simple validation
        for (int i = 0; i < 4; i++) {
          if (**pos == '\\' || **pos == '"') {
            printf("failed to skip due to invalid unicdoe escape: %s\n", start);
            return false;
          }
          *pos += 1;
        }
        break;

      default:
        printf("failed to skip due to escap (%c) : %s\n", **pos, start);
        return false;
      }
    } else if (**pos == '"') {
      *pos += 1;
      return true;
    } else {
      *pos += 1;
    }
  }
}

/* Skip a single valid json value */
bool json_skip(char **pos) {
  skipws(pos);
  float f;
  Str s;
  bool first=true;

  //dbg("skipping json, pointer at: %p, char: %c", *pos, **pos);
  switch(**pos) {
  case '-':
  case '0': case '1': case '2': case '3': case'4':
  case '5': case '6': case '7': case '8': case '9':
    return json_float(pos, &f);

  case '"':
    return json_skip_string(pos);

  case '{': {
    *pos += 1;
    while(json_at(pos) != '}') {
      if(!first) {
        if(!json_expect_consume(pos, ',')) return false;
      }
      first = false;
      if(!json_expect_consume(pos, '"')) return false;
      s = parse_string(*pos);
      if(!s.success) return false;
      *pos = s.after;
      if(!json_expect_consume(pos, ':')) return false;
      if(!json_skip(pos)) return false; // skip the value
    }
    return json_expect_consume(pos, '}');
  }

  case '[': {
    *pos += 1;
    while(json_at(pos) != ']') {

      if(!first) {
        if(!json_expect_consume(pos, ',')) return false;
      }
      first = false;
      if(!json_skip(pos)) return false;
    }
    return json_expect_consume(pos, ']');
  }
  default:
    if(looking_at(*pos, "null") && !is_alphanumeric((*pos)[4])) {
      *pos = *pos + 4;
      return true;
    }
    if(looking_at(*pos, "true") && !is_alphanumeric((*pos)[4])) {
      *pos = *pos + 4;
      return true;
    }
    if(looking_at(*pos, "false") && !is_alphanumeric((*pos)[5])) {
      *pos = *pos + 5;
      return true;
    }
    return false;
  }
  return false;
}

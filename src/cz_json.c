/*
 * Reading JSON in place. Nothing is allocated and nothing is copied until a value is asked for:
 * a value is a span of the original text. The reader accepts what the platform and the other
 * SDKs send; text that is not JSON simply yields no members.
 */
#include "cz_internal.h"

#include <stdio.h>

static const char *skip_space(const char *at, const char *end)
{
    while (at < end && (*at == ' ' || *at == '\t' || *at == '\r' || *at == '\n')) {
        at++;
    }
    return at;
}

/* Returns the position after the string that starts at `at` (which points at its opening quote), or NULL. */
static const char *skip_string(const char *at, const char *end)
{
    for (at++; at < end; at++) {
        if (*at == '\\') {
            at++;
        } else if (*at == '"') {
            return at + 1;
        }
    }
    return NULL;
}

/* Returns the position after the value that starts at `at`, or NULL when the text is not well formed. */
static const char *skip_value(const char *at, const char *end, int depth)
{
    at = skip_space(at, end);
    if (at >= end || depth > 16) {
        return NULL;
    }
    if (*at == '"') {
        return skip_string(at, end);
    }
    if (*at == '{' || *at == '[') {
        char close = *at == '{' ? '}' : ']';
        bool object = *at == '{';
        at = skip_space(at + 1, end);
        if (at < end && *at == close) {
            return at + 1;
        }
        while (at != NULL && at < end) {
            if (object) {
                at = skip_space(at, end);
                if (at >= end || *at != '"') {
                    return NULL;
                }
                at = skip_string(at, end);
                if (at == NULL) {
                    return NULL;
                }
                at = skip_space(at, end);
                if (at >= end || *at != ':') {
                    return NULL;
                }
                at++;
            }
            at = skip_value(at, end, depth + 1);
            if (at == NULL) {
                return NULL;
            }
            at = skip_space(at, end);
            if (at < end && *at == ',') {
                at++;
                continue;
            }
            return at < end && *at == close ? at + 1 : NULL;
        }
        return NULL;
    }
    /* A number or one of true, false, null: everything up to the next delimiter. */
    const char *start = at;
    while (at < end && *at != ',' && *at != '}' && *at != ']' && *at != ' ' && *at != '\t' && *at != '\r' && *at != '\n') {
        at++;
    }
    return at > start ? at : NULL;
}

bool cz_json_member(cz_span object, const char *key, cz_span *value)
{
    if (object.at == NULL) {
        return false;
    }
    const char *end = object.at + object.length;
    const char *at = skip_space(object.at, end);
    size_t key_length = strlen(key);
    if (at >= end || *at != '{') {
        return false;
    }
    at = skip_space(at + 1, end);
    while (at < end && *at == '"') {
        const char *name = at + 1;
        const char *after_name = skip_string(at, end);
        if (after_name == NULL) {
            return false;
        }
        size_t name_length = (size_t)(after_name - 1 - name);
        at = skip_space(after_name, end);
        if (at >= end || *at != ':') {
            return false;
        }
        const char *start = skip_space(at + 1, end);
        const char *after_value = skip_value(start, end, 0);
        if (after_value == NULL) {
            return false;
        }
        /* Member names in this protocol contain no escapes, so they can be compared as they are. */
        if (name_length == key_length && memcmp(name, key, key_length) == 0) {
            value->at = start;
            value->length = (size_t)(after_value - start);
            return true;
        }
        at = skip_space(after_value, end);
        if (at < end && *at == ',') {
            at = skip_space(at + 1, end);
        }
    }
    return false;
}

bool cz_json_next(cz_span array, size_t *cursor, cz_span *element)
{
    if (array.at == NULL) {
        return false;
    }
    const char *end = array.at + array.length;
    const char *at;
    if (*cursor == 0) {
        at = skip_space(array.at, end);
        if (at >= end || *at != '[') {
            return false;
        }
        at++;
    } else {
        at = array.at + *cursor;
    }
    at = skip_space(at, end);
    if (at < end && *at == ',') {
        at = skip_space(at + 1, end);
    }
    if (at >= end || *at == ']') {
        return false;
    }
    const char *after = skip_value(at, end, 0);
    if (after == NULL) {
        return false;
    }
    element->at = at;
    element->length = (size_t)(after - at);
    *cursor = (size_t)(after - array.at);
    return true;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool cz_json_string(cz_span value, char *out, size_t capacity)
{
    if (value.at == NULL || value.length < 2 || value.at[0] != '"' || capacity == 0) {
        return false;
    }
    const char *at = value.at + 1;
    const char *end = value.at + value.length - 1;
    size_t written = 0;
    while (at < end) {
        uint32_t code = (uint8_t)*at++;
        if (code == '\\' && at < end) {
            char escape = *at++;
            switch (escape) {
            case 'n': code = '\n'; break;
            case 't': code = '\t'; break;
            case 'r': code = '\r'; break;
            case 'b': code = '\b'; break;
            case 'f': code = '\f'; break;
            case 'u': {
                if (end - at < 4) {
                    return false;
                }
                code = 0;
                for (int i = 0; i < 4; i++) {
                    int digit = hex_digit(at[i]);
                    if (digit < 0) {
                        return false;
                    }
                    code = (code << 4) | (uint32_t)digit;
                }
                at += 4;
                /* Characters outside the basic plane come as a pair; anything unpaired becomes U+FFFD. */
                if (code >= 0xd800 && code <= 0xdbff && end - at >= 6 && at[0] == '\\' && at[1] == 'u') {
                    uint32_t low = 0;
                    for (int i = 0; i < 4; i++) {
                        int digit = hex_digit(at[2 + i]);
                        low = digit < 0 ? 0 : (low << 4) | (uint32_t)digit;
                    }
                    if (low >= 0xdc00 && low <= 0xdfff) {
                        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                        at += 6;
                    }
                }
                if (code >= 0xd800 && code <= 0xdfff) {
                    code = 0xfffd;
                }
                break;
            }
            default: code = (uint8_t)escape; break; /* \" \\ \/ */
            }
            if (code >= 0x80) {
                uint8_t utf8[4];
                size_t count;
                if (code < 0x800) {
                    utf8[0] = (uint8_t)(0xc0 | (code >> 6));
                    utf8[1] = (uint8_t)(0x80 | (code & 0x3f));
                    count = 2;
                } else if (code < 0x10000) {
                    utf8[0] = (uint8_t)(0xe0 | (code >> 12));
                    utf8[1] = (uint8_t)(0x80 | ((code >> 6) & 0x3f));
                    utf8[2] = (uint8_t)(0x80 | (code & 0x3f));
                    count = 3;
                } else {
                    utf8[0] = (uint8_t)(0xf0 | (code >> 18));
                    utf8[1] = (uint8_t)(0x80 | ((code >> 12) & 0x3f));
                    utf8[2] = (uint8_t)(0x80 | ((code >> 6) & 0x3f));
                    utf8[3] = (uint8_t)(0x80 | (code & 0x3f));
                    count = 4;
                }
                if (written + count >= capacity) {
                    return false;
                }
                memcpy(out + written, utf8, count);
                written += count;
                continue;
            }
        }
        if (written + 1 >= capacity) {
            return false;
        }
        out[written++] = (char)code;
    }
    out[written] = '\0';
    return true;
}

bool cz_json_int(cz_span value, int64_t *out)
{
    if (value.at == NULL || value.length == 0 || value.length > 20) {
        return false;
    }
    size_t i = 0;
    bool negative = value.at[0] == '-';
    if (negative) {
        i++;
    }
    if (i >= value.length) {
        return false;
    }
    int64_t result = 0;
    for (; i < value.length; i++) {
        char c = value.at[i];
        if (c == '.' || c == 'e' || c == 'E') {
            break; /* the integral part is all this protocol needs */
        }
        if (c < '0' || c > '9') {
            return false;
        }
        result = result * 10 + (c - '0');
    }
    *out = negative ? -result : result;
    return true;
}

bool cz_json_bool(cz_span value, bool *out)
{
    if (value.at != NULL && value.length == 4 && memcmp(value.at, "true", 4) == 0) {
        *out = true;
        return true;
    }
    if (value.at != NULL && value.length == 5 && memcmp(value.at, "false", 5) == 0) {
        *out = false;
        return true;
    }
    return false;
}

bool cz_json_contains(cz_span array, const char *text)
{
    size_t cursor = 0;
    cz_span element;
    char item[CZ_NAME_SIZE];
    while (cz_json_next(array, &cursor, &element)) {
        if (cz_json_string(element, item, sizeof item) && strcmp(item, text) == 0) {
            return true;
        }
    }
    return false;
}

int cz_json_quote(char *out, size_t capacity, const char *text)
{
    size_t written = 0;
    if (capacity < 3) {
        return -1;
    }
    out[written++] = '"';
    for (const unsigned char *at = (const unsigned char *)text; *at != '\0'; at++) {
        char escaped[7];
        size_t count;
        if (*at == '"' || *at == '\\') {
            escaped[0] = '\\';
            escaped[1] = (char)*at;
            count = 2;
        } else if (*at < 0x20) {
            count = (size_t)snprintf(escaped, sizeof escaped, "\\u%04x", *at);
        } else {
            escaped[0] = (char)*at;
            count = 1;
        }
        if (written + count + 2 > capacity) {
            return -1;
        }
        memcpy(out + written, escaped, count);
        written += count;
    }
    out[written++] = '"';
    out[written] = '\0';
    return (int)written;
}

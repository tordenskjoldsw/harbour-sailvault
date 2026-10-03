#ifndef SAILVAULT_CORE_H
#define SAILVAULT_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Static, NUL-terminated string. Valid for the process lifetime, never free it. */
const char *sailvault_core_version(void);

/* Status codes returned by the functions below. */
enum {
    SV_OK = 0,
    SV_INVALID_ARGUMENT = 1,
    SV_NOT_KDBX = 2,
    SV_KDBX3_UNSUPPORTED = 3,
    SV_UNSUPPORTED_FORMAT = 4,
    SV_INVALID_CREDENTIALS = 5,
    SV_INVALID_KEY_FILE = 6,
    SV_CORRUPTED = 7,
    SV_LIMIT_EXCEEDED = 8,
    SV_NOT_FOUND = 9,
    /* The serialized file did not decrypt back to the same content; nothing
     * was handed out. */
    SV_WRITE_FAILED = 10,
    SV_RANDOM_UNAVAILABLE = 11
};

/* Character classes for sv_generate_password, combined with bitwise or. */
enum {
    SV_CLASS_LOWER = 1,
    SV_CLASS_UPPER = 2,
    SV_CLASS_DIGITS = 4,
    SV_CLASS_SYMBOLS = 8
};

enum { SV_UUID_LENGTH = 16 };

/* Columns for sv_list_text. */
enum { SV_COLUMN_TITLE = 0, SV_COLUMN_USER_NAME = 1, SV_COLUMN_GROUP = 2 };

typedef struct SvDatabase SvDatabase;
typedef struct SvList SvList;
typedef struct SvFieldList SvFieldList;

/* UTF-8, not NUL-terminated. Release with sv_string_free, which zeroizes it. */
typedef struct SvString {
    uint8_t *data;
    size_t length;
} SvString;

/* A serialized database file. Release with sv_bytes_free. */
typedef struct SvBytes {
    uint8_t *data;
    size_t length;
} SvBytes;

/* A field of a new entry: UTF-8 key and value, not NUL-terminated. */
typedef struct SvField {
    const uint8_t *key;
    size_t key_length;
    const uint8_t *value;
    size_t value_length;
} SvField;

/* Runs the KDF; call off the UI thread. A database handle is not thread-safe:
 * use it from one thread at a time. */
int32_t sv_database_open(const uint8_t *data, size_t data_length,
                         const uint8_t *password, size_t password_length, bool has_password,
                         const uint8_t *key_file, size_t key_file_length,
                         SvDatabase **out);
/* Locks: drops and zeroizes all decrypted data. */
void sv_database_free(SvDatabase *database);

int32_t sv_database_search(const SvDatabase *database, const uint8_t *query, size_t query_length,
                           SvList **out);
/* group_uuid NULL means the root group. Subgroups come before entries. */
int32_t sv_database_group(const SvDatabase *database, const uint8_t *group_uuid, SvList **out);

size_t sv_list_length(const SvList *list);
int32_t sv_list_uuid(const SvList *list, size_t index, uint8_t *uuid_out);
bool sv_list_is_group(const SvList *list, size_t index);
int32_t sv_list_text(const SvList *list, size_t index, uint32_t column, SvString *out);
void sv_list_free(SvList *list);

/* Field names and protection flags of an entry, without values. */
int32_t sv_database_fields(const SvDatabase *database, const uint8_t *entry_uuid, SvFieldList **out);
size_t sv_field_list_length(const SvFieldList *fields);
int32_t sv_field_list_key(const SvFieldList *fields, size_t index, SvString *out);
bool sv_field_list_is_protected(const SvFieldList *fields, size_t index);
void sv_field_list_free(SvFieldList *fields);

/* One field value, for showing or copying it. Free it as soon as possible. */
int32_t sv_database_field_value(const SvDatabase *database, const uint8_t *entry_uuid,
                                const uint8_t *key, size_t key_length, SvString *out);

void sv_string_free(SvString string);

/* Adds an entry to a group (group_uuid NULL means the root group), in memory
 * only until sv_database_save. The five standard fields (Title, UserName,
 * Password, URL, Notes) are always written; now is in seconds since the Unix
 * epoch. Writes the entry's UUID to uuid_out. */
int32_t sv_database_add_entry(SvDatabase *database, const uint8_t *group_uuid,
                              const SvField *fields, size_t field_count, int64_t now,
                              uint8_t *uuid_out);

/* Sets fields of an entry. A changed entry keeps its previous state as a
 * history item; changed_out says whether anything changed. */
int32_t sv_database_update_entry(SvDatabase *database, const uint8_t *entry_uuid,
                                 const SvField *fields, size_t field_count, int64_t now,
                                 bool *changed_out);
/* Moves an entry or a group (with everything in it) to the recycle bin, or
 * removes it for good when it is already there, is or holds the bin, or the
 * bin is disabled (permanent_out says which). The root group is refused. */
int32_t sv_database_delete_item(SvDatabase *database, const uint8_t *uuid, int64_t now,
                                bool *permanent_out);
int32_t sv_database_delete_is_permanent(const SvDatabase *database, const uint8_t *uuid,
                                        bool *out);

/* Serializes the database with fresh seeds and verifies it by decrypting it
 * again. Runs the KDF; call off the UI thread. Other threads may read the
 * database meanwhile but must not modify or free it. */
int32_t sv_database_save(const SvDatabase *database, SvBytes *out);
void sv_bytes_free(SvBytes bytes);

/* A random password of length characters (4 to 128) drawn from the selected
 * SV_CLASS_* classes, each used at least once. Free it with sv_string_free. */
int32_t sv_generate_password(size_t length, uint32_t classes, SvString *out);

#ifdef __cplusplus
}
#endif

#endif /* SAILVAULT_CORE_H */

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
    SV_RANDOM_UNAVAILABLE = 11,
    /* The file is not a Bitwarden/Vaultwarden JSON export. */
    SV_NOT_AN_EXPORT = 12
};

/* Kinds of Bitwarden exports, from sv_bitwarden_export_kind. */
enum {
    SV_EXPORT_UNENCRYPTED = 0,
    SV_EXPORT_PASSWORD_PROTECTED = 1,
    /* Encrypted with the account key; cannot be imported. */
    SV_EXPORT_ACCOUNT_RESTRICTED = 2
};

/* Key derivation levels for sv_database_create: Argon2id with 256 MiB and 3
 * iterations, 512 MiB and 4, or 1 GiB and 4 (about 1, 2.5 and 5 s per
 * unlock and save on the Jolla Phone). */
enum { SV_KDF_STANDARD = 0, SV_KDF_HIGH = 1, SV_KDF_MAXIMUM = 2 };

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
typedef struct SvImport SvImport;

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
/* Creates a new, empty database (KDBX 4.0, AES-256, Argon2id at an SV_KDF_*
 * level) protected by a non-empty password and serializes it. Runs the KDF; call off the UI
 * thread. *out receives the unlocked handle, *file_out the file to write. */
int32_t sv_database_create(const uint8_t *password, size_t password_length, const uint8_t *name,
                           size_t name_length, uint32_t kdf_level, int64_t now, SvDatabase **out,
                           SvBytes *file_out);
/* Locks: drops and zeroizes all decrypted data. */
void sv_database_free(SvDatabase *database);

int32_t sv_database_search(const SvDatabase *database, const uint8_t *query, size_t query_length,
                           SvList **out);
/* group_uuid NULL means the root group. Subgroups come before entries. */
int32_t sv_database_group(const SvDatabase *database, const uint8_t *group_uuid, SvList **out);
/* Every group outside the recycle bin, parents first, as move targets; with
 * exclude_uuid set, without that group and its subgroups. The group column
 * holds the path of the parent groups. */
int32_t sv_database_groups(const SvDatabase *database, const uint8_t *exclude_uuid, SvList **out);

size_t sv_list_length(const SvList *list);
int32_t sv_list_uuid(const SvList *list, size_t index, uint8_t *uuid_out);
bool sv_list_is_group(const SvList *list, size_t index);
int32_t sv_list_text(const SvList *list, size_t index, uint32_t column, SvString *out);
void sv_list_free(SvList *list);

/* Entry versions: -1 is the current state, 0 and up index the history items,
 * oldest first. */
enum { SV_CURRENT_VERSION = -1 };

/* Field names and protection flags of an entry version, without values. */
int32_t sv_database_fields(const SvDatabase *database, const uint8_t *entry_uuid, int64_t version,
                           SvFieldList **out);
size_t sv_field_list_length(const SvFieldList *fields);
int32_t sv_field_list_key(const SvFieldList *fields, size_t index, SvString *out);
bool sv_field_list_is_protected(const SvFieldList *fields, size_t index);
void sv_field_list_free(SvFieldList *fields);

/* One field value, for showing or copying it. Free it as soon as possible. */
int32_t sv_database_field_value(const SvDatabase *database, const uint8_t *entry_uuid,
                                int64_t version, const uint8_t *key, size_t key_length,
                                SvString *out);
int32_t sv_database_history_length(const SvDatabase *database, const uint8_t *entry_uuid,
                                   size_t *out);
/* Seconds since the Unix epoch. */
int32_t sv_database_modification_time(const SvDatabase *database, const uint8_t *entry_uuid,
                                      int64_t version, int64_t *out);

void sv_string_free(SvString string);

/* Adds an entry to a group (group_uuid NULL means the root group), in memory
 * only until sv_database_save. The five standard fields (Title, UserName,
 * Password, URL, Notes) are always written; now is in seconds since the Unix
 * epoch. Writes the entry's UUID to uuid_out. Refused inside the recycle
 * bin. */
int32_t sv_database_add_entry(SvDatabase *database, const uint8_t *group_uuid,
                              const SvField *fields, size_t field_count, int64_t now,
                              uint8_t *uuid_out);

/* Adds a group (parent_uuid NULL means the root group) and writes its UUID to
 * uuid_out. Refused inside the recycle bin and for an empty name. */
int32_t sv_database_add_group(SvDatabase *database, const uint8_t *parent_uuid,
                              const uint8_t *name, size_t name_length, int64_t now,
                              uint8_t *uuid_out);
/* Whether an entry or group is the recycle bin or inside it; no new entries
 * or groups are added there. */
int32_t sv_database_in_recycle_bin(const SvDatabase *database, const uint8_t *uuid, bool *out);

/* Sets fields of an entry. A changed entry keeps its previous state as a
 * history item; changed_out says whether anything changed. */
int32_t sv_database_update_entry(SvDatabase *database, const uint8_t *entry_uuid,
                                 const SvField *fields, size_t field_count, int64_t now,
                                 bool *changed_out);
/* Moves an entry to the end of another group; moved_out is false when it is
 * already there. */
int32_t sv_database_move_entry(SvDatabase *database, const uint8_t *entry_uuid,
                               const uint8_t *group_uuid, int64_t now, bool *moved_out);
/* Moves an entry or a group (with everything in it) to the recycle bin, or
 * removes it for good when it is already there, is or holds the bin, or the
 * bin is disabled (permanent_out says which). The root group is refused. */
int32_t sv_database_delete_item(SvDatabase *database, const uint8_t *uuid, int64_t now,
                                bool *permanent_out);
int32_t sv_database_delete_is_permanent(const SvDatabase *database, const uint8_t *uuid,
                                        bool *out);

/* Groups: a rename updates the modification time; a move takes the content
 * along and is refused for the root group and into the group itself. */
int32_t sv_database_rename_group(SvDatabase *database, const uint8_t *group_uuid,
                                 const uint8_t *name, size_t name_length, int64_t now,
                                 bool *changed_out);
int32_t sv_database_move_group(SvDatabase *database, const uint8_t *group_uuid,
                               const uint8_t *parent_uuid, int64_t now, bool *moved_out);

/* Recycle bin: restore moves an entry or group back to the group it was
 * deleted from, or to the root group; emptying removes everything in the bin
 * for good and records it as deleted. sv_database_recycle_bin gives
 * SV_NOT_FOUND when there is no bin. */
int32_t sv_database_restore(SvDatabase *database, const uint8_t *uuid, int64_t now);
int32_t sv_database_empty_recycle_bin(SvDatabase *database, int64_t now, bool *changed_out);
int32_t sv_database_recycle_bin(const SvDatabase *database, uint8_t *uuid_out);

/* Serializes the database with fresh seeds and verifies it by decrypting it
 * again. Runs the KDF; call off the UI thread. Other threads may read the
 * database meanwhile but must not modify or free it. */
int32_t sv_database_save(const SvDatabase *database, SvBytes *out);
void sv_bytes_free(SvBytes bytes);

/* A random password of length characters (4 to 128) drawn from the selected
 * SV_CLASS_* classes, each used at least once. Free it with sv_string_free. */
int32_t sv_generate_password(size_t length, uint32_t classes, SvString *out);

/* Bitwarden/Vaultwarden JSON exports. The kind comes from the top level only.
 * sv_bitwarden_read decrypts a password-protected export (a wrong password
 * gives SV_INVALID_CREDENTIALS) and maps it to a group named group_name; it
 * runs the export's KDF, so call it off the UI thread. sv_database_import
 * merges that group in one step into the root group's group of the same
 * name, created when missing: entries are matched by the Bitwarden item ID,
 * the newer side wins and the other becomes a history item, deleted entries
 * stay deleted and nothing is removed. It writes how many entries were added
 * and updated. sv_import_free zeroizes the import. */
int32_t sv_bitwarden_export_kind(const uint8_t *data, size_t length, int32_t *kind_out);
int32_t sv_bitwarden_read(const uint8_t *data, size_t length, const uint8_t *password,
                          size_t password_length, bool has_password, const uint8_t *group_name,
                          size_t group_name_length, SvImport **out);
int32_t sv_database_import(SvDatabase *database, const SvImport *import, int64_t now,
                           size_t *added_out, size_t *updated_out);
void sv_import_free(SvImport *import);

#ifdef __cplusplus
}
#endif

#endif /* SAILVAULT_CORE_H */

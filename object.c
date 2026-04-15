// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(id_out->hash, &ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

static const char *object_type_to_string(ObjectType type) {
    switch (type) {
        case OBJ_BLOB:   return "blob";
        case OBJ_TREE:   return "tree";
        case OBJ_COMMIT: return "commit";
        default:         return NULL;
    }
}

static int object_type_from_string(const char *s, ObjectType *type_out) {
    if (strcmp(s, "blob") == 0) {
        *type_out = OBJ_BLOB;
        return 0;
    }
    if (strcmp(s, "tree") == 0) {
        *type_out = OBJ_TREE;
        return 0;
    }
    if (strcmp(s, "commit") == 0) {
        *type_out = OBJ_COMMIT;
        return 0;
    }
    return -1;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    if (!data || !id_out) return -1;

    const char *type_str = object_type_to_string(type);
    if (!type_str) return -1;

    /* 1. Build full object = header + '\0' + data */
    char header[100];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) return -1;

    size_t total_len = (size_t)header_len + 1 + len;
    unsigned char *full_obj = malloc(total_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, (size_t)header_len + 1); /* includes '\0' */
    memcpy(full_obj + header_len + 1, data, len);

    /* 2. Compute hash of full object */
    compute_hash(full_obj, total_len, id_out);

    /* 3. Deduplicate */
    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    /* Build final path */
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    /* 4. Create shard directory */
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s", final_path);
    char *slash = strrchr(shard_dir, '/');
    if (!slash) {
        free(full_obj);
        return -1;
    }
    *slash = '\0';

    if (mkdir(shard_dir, 0755) != 0) {
        if (access(shard_dir, F_OK) != 0) {
            free(full_obj);
            return -1;
        }
    }

    /* 5. Write temp file */
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/.tmpXXXXXX", shard_dir);

    int temp_fd = mkstemp(temp_path);
    if (temp_fd < 0) {
        free(full_obj);
        return -1;
    }

    size_t written_total = 0;
    while (written_total < total_len) {
        ssize_t w = write(temp_fd, full_obj + written_total, total_len - written_total);
        if (w < 0) {
            close(temp_fd);
            unlink(temp_path);
            free(full_obj);
            return -1;
        }
        written_total += (size_t)w;
    }

    /* 6. fsync temp file */
    if (fsync(temp_fd) != 0) {
        close(temp_fd);
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    if (close(temp_fd) != 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    /* 7. Atomic rename */
    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_obj);
        return -1;
    }

    /* 8. fsync shard directory */
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    /* 9. id_out already set */
    free(full_obj);
    return 0;
}

// Read an object from the store.
//
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    if (!id || !type_out || !data_out || !len_out) return -1;

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long file_size_long = ftell(fp);
    if (file_size_long < 0) {
        fclose(fp);
        return -1;
    }

    size_t file_size = (size_t)file_size_long;
    rewind(fp);

    unsigned char *buf = malloc(file_size);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    if (file_size > 0) {
        size_t read_bytes = fread(buf, 1, file_size, fp);
        if (read_bytes != file_size) {
            fclose(fp);
            free(buf);
            return -1;
        }
    }
    fclose(fp);

    /* 4. Verify integrity */
    ObjectID computed;
    compute_hash(buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    /* 3. Parse header */
    unsigned char *nul = memchr(buf, '\0', file_size);
    if (!nul) {
        free(buf);
        return -1;
    }

    size_t header_len = (size_t)(nul - buf);
    char *header = malloc(header_len + 1);
    if (!header) {
        free(buf);
        return -1;
    }
    memcpy(header, buf, header_len);
    header[header_len] = '\0';

    char type_str[16];
    size_t parsed_len = 0;
    if (sscanf(header, "%15s %zu", type_str, &parsed_len) != 2) {
        free(header);
        free(buf);
        return -1;
    }

    if (object_type_from_string(type_str, type_out) != 0) {
        free(header);
        free(buf);
        return -1;
    }

    size_t data_offset = header_len + 1;
    if (data_offset > file_size) {
        free(header);
        free(buf);
        return -1;
    }

    size_t actual_data_len = file_size - data_offset;
    if (actual_data_len != parsed_len) {
        free(header);
        free(buf);
        return -1;
    }

    void *out = malloc(parsed_len);
    if (!out && parsed_len > 0) {
        free(header);
        free(buf);
        return -1;
    }

    if (parsed_len > 0) {
        memcpy(out, buf + data_offset, parsed_len);
    }

    *data_out = out;
    *len_out = parsed_len;

    free(header);
    free(buf);
    return 0;
}

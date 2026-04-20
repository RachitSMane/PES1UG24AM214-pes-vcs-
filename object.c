#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

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
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

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

// ─── TODO: Implement these ───────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Convert ObjectType enum to string
    const char *type_str;
    if (type == OBJ_BLOB)        type_str = "blob";
    else if (type == OBJ_TREE)   type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // Step 2: Build header "blob 16\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    // Step 3: Build full buffer = header + '\0' + data
    size_t full_len = header_len + 1 + len;
    uint8_t *full = malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    full[header_len] = '\0';
    memcpy(full + header_len + 1, data, len);

    // Step 4: Compute hash
    compute_hash(full, full_len, id_out);

    // Step 5: Deduplicate
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Step 6: Build paths
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(dir_path, 0755);

    char file_path[512];
    object_path(id_out, file_path, sizeof(file_path));

    // Step 7: Write to temp file, fsync, rename atomically
    char tmp_path[516];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", file_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(full); return -1; }

    if (write(fd, full, full_len) != (ssize_t)full_len) {
        close(fd); free(full); return -1;
    }
    fsync(fd);
    close(fd);
    free(full);

    if (rename(tmp_path, file_path) != 0) return -1;

    // Step 8: fsync the directory
    int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Get file path
    char file_path[512];
    object_path(id, file_path, sizeof(file_path));

    // Step 2: Open and read entire file
    FILE *f = fopen(file_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t full_len = ftell(f);
    rewind(f);

    uint8_t *full = malloc(full_len);
    if (!full) { fclose(f); return -1; }

    size_t bytes_read = fread(full, 1, full_len, f);
    fclose(f);
    if (bytes_read != full_len) { free(full); return -1; }

    // Step 3: Verify integrity — recompute hash and compare
    ObjectID computed;
    compute_hash(full, full_len, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(full); return -1;
    }

    // Step 4: Find space separator in header
    uint8_t *space = memchr(full, ' ', full_len);
    if (!space) { free(full); return -1; }

    // Step 5: Find null byte separating header from data
    uint8_t *null_byte = memchr(space, '\0', full_len - (space - full));
    if (!null_byte) { free(full); return -1; }

    // Step 6: Parse type string into enum
    size_t type_len = space - full;
    char type_str[16] = {0};
    memcpy(type_str, full, type_len);

    if (strcmp(type_str, "blob") == 0)        *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0)   *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else { free(full); return -1; }

    // Step 7: Extract data length and copy data
    *len_out = (size_t)atoi((char *)(space + 1));
    *data_out = malloc(*len_out + 1);        // +1 for null terminator
    if (!*data_out) { free(full); return -1; }
    memcpy(*data_out, null_byte + 1, *len_out);
    ((uint8_t *)*data_out)[*len_out] = '\0'; // null terminate for string safety

    free(full);
    return 0;
}

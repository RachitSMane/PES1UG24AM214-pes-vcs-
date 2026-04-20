// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256
#include "tree.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
extern int index_load(Index *index) __attribute__((weak));
// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// HINTS - Useful functions and concepts for this phase:
//   - index_load      : load the staged files into memory
//   - strchr          : find the first '/' in a path to separate directories from files
//   - strncmp         : compare prefixes to group files belonging to the same subdirectory
//   - Recursion       : you will likely want to create a recursive helper function 
//                       (e.g., `write_tree_level(entries, count, depth)`) to handle nested dirs.
//   - tree_serialize  : convert your populated Tree struct into a binary buffer
//   - object_write    : save that binary buffer to the store as OBJ_TREE
//
// Returns 0 on success, -1 on error.
// Helper: write one level of the tree (entries sharing the same directory prefix)
static int write_tree_level(IndexEntry *entries, int count, const char *prefix, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        const char *path = entries[i].path;

        // Strip the prefix to get the relative path at this level
        const char *rel = path;
        if (prefix && strlen(prefix) > 0) {
            rel = path + strlen(prefix) + 1; // skip "prefix/"
        }

        // Check if this entry is in a subdirectory at this level
        char *slash = strchr(rel, '/');

        if (!slash) {
            // It's a file at this level — add directly
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            snprintf(te->name, sizeof(te->name), "%.*s", (int)(sizeof(te->name) - 1), rel);
            i++;
        } else {
            // It's inside a subdirectory — collect all entries with same subdir
            char subdir[256];
            size_t subdir_len = slash - rel;
            memcpy(subdir, rel, subdir_len);
            subdir[subdir_len] = '\0';

            // Build full prefix for this subdir
            char new_prefix[512];
            if (prefix && strlen(prefix) > 0)
                snprintf(new_prefix, sizeof(new_prefix), "%s/%s", prefix, subdir);
            else
                snprintf(new_prefix, sizeof(new_prefix), "%s", subdir);

            // Count how many entries belong to this subdir
            int j = i;
            while (j < count) {
                const char *p = entries[j].path;
                const char *r = p;
                if (prefix && strlen(prefix) > 0)
                    r = p + strlen(prefix) + 1;
                if (strncmp(r, subdir, subdir_len) == 0 && r[subdir_len] == '/')
                    j++;
                else
                    break;
            }

            // Recurse to build the subtree
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, new_prefix, &sub_id) != 0)
                return -1;

            // Add subtree entry
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = 0040000;
            te->hash = sub_id;
            snprintf(te->name, sizeof(te->name), "%s", subdir);
            i = j;
        }
    }

    // Serialize and write this tree level
    void *data;
    size_t data_len;
    if (tree_serialize(&tree, &data, &data_len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, data_len, id_out);
    free(data);
    return rc;
}

// Weak symbol so test_tree links without index.o
// When linked with index.o (in pes binary), the real index_load is used
__attribute__((weak)) int index_load(Index *index) {
    (void)index;
    return -1;
}

int tree_from_index(ObjectID *id_out) {
    Index idx;
    memset(&idx, 0, sizeof(idx));
    if (index_load(&idx) != 0) return -1;
    if (idx.count == 0) return -1;
    return write_tree_level(idx.entries, idx.count, "", id_out);
}

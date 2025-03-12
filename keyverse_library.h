#ifndef KEYVERSE_LIBRARY_H
#define KEYVERSE_LIBRARY_H

#ifdef _WIN32
#define KEYVERSE_API __declspec(dllexport)
#else
#define KEYVERSE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque type representing a Keyverse context.
typedef struct KeyverseContext KeyverseContext;

// Create a new Keyverse context using the given configuration file.
// The config file should be a JSON file that (at minimum) provides the key "verseFolderPath"
// and optionally an "encryptionKey" (if not provided, one is generated).
// Returns a pointer to the new context or NULL on failure.
KEYVERSE_API KeyverseContext* kv_create_context(const char* configFilePath);

// Destroy a Keyverse context.
KEYVERSE_API void kv_destroy_context(KeyverseContext* ctx);

// Set (or update) a key–value pair in the context. The data is immediately saved to disk.
// Returns 0 on success and nonzero on error.
KEYVERSE_API int kv_set(KeyverseContext* ctx, const char* key, const char* value);

// Get the value associated with the given key.
// Returns a newly allocated string (using new[]) that must later be freed via kv_free_string.
// If the key is not found, a string "Key not found." is returned.
KEYVERSE_API char* kv_get(KeyverseContext* ctx, const char* key);

// List all key–value pairs as a text block.
// Returns a newly allocated string that must be freed via kv_free_string.
KEYVERSE_API char* kv_list_all(KeyverseContext* ctx);

// Save the current key–value data to disk (both the encrypted verse file and data file).
// Returns 0 on success, nonzero on error.
KEYVERSE_API int kv_save(KeyverseContext* ctx);

// Return an encrypted backup of the key–value data.
// Returns a newly allocated string that must be freed via kv_free_string.
KEYVERSE_API char* kv_backup(KeyverseContext* ctx);

// Generate a GUID.
// Returns a newly allocated string that must be freed via kv_free_string.
KEYVERSE_API char* kv_generate_guid(void);

// Free a string previously allocated by the library.
KEYVERSE_API void kv_free_string(char* str);

#ifdef __cplusplus
}
#endif

#endif // KEYVERSE_LIBRARY_H

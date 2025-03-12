# Keyverse Library

## Overview

Keyverse Library is a C++ implementation for secure key-value storage. It provides functionalities such as encryption, decryption, GUID generation, and data persistence using AES-128-CBC encryption with OpenSSL.

## Features

- **Configuration Handling:** Reads configurations from a JSON file.
- **Encryption & Decryption:** Utilizes AES-128-CBC encryption.
- **Data Persistence:** Saves and retrieves encrypted key-value data.
- **GUID Generation:** Generates unique identifiers.
- **C API Integration:** Provides an external C API for interaction.

## Dependencies

To build and run Keyverse Library, ensure you have the following dependencies:

- **C++ Standard Library**
- **OpenSSL** (for encryption & decryption)
- **Boost.Asio** (for networking)
- **nlohmann/json** (for JSON parsing)
- **Filesystem Support** (C++17 or later)

## Installation

1. Clone this repository:

   ```sh
   git clone https://github.com/your-repo/keyverse-library.git
   cd keyverse-library
   ```

2. Install dependencies:

   - On Ubuntu/Debian:
     ```sh
     sudo apt-get install libssl-dev libboost-all-dev
     ```
   - On macOS:
     ```sh
     brew install openssl boost
     ```

3. Compile the library:

   ```sh
   g++ -std=c++17 -I/usr/include -L/usr/lib -lssl -lcrypto -o keyverse keyverse_library.cpp
   ```

## Usage

### Creating a Context

```cpp
KeyverseContext* ctx = kv_create_context("config.json");
if (!ctx) {
    std::cerr << "Failed to create Keyverse context" << std::endl;
}
```

### Storing a Key-Value Pair

```cpp
kv_set(ctx, "username", "john_doe");
```

### Retrieving a Value

```cpp
char* value = kv_get(ctx, "username");
std::cout << "Value: " << value << std::endl;
kv_free_string(value);
```

### Generating a GUID

```cpp
char* guid = kv_generate_guid();
std::cout << "Generated GUID: " << guid << std::endl;
kv_free_string(guid);
```

### Saving Data

```cpp
kv_save(ctx);
```

### Destroying the Context

```cpp
kv_destroy_context(ctx);
```

## License

This project is licensed under the MIT License.

---

For further details, refer to the code documentation.

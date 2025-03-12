#include "keyverse_library.h"
#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include "nlohmann/json.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <random>
#include <iomanip>
#include <iostream>
#include "log.h"
#include <boost/asio.hpp>
#include <filesystem>

// Use nlohmann::json for JSON operations.
using json = nlohmann::json;

// ----------------------------------------------------------------------------
// The following namespace reimplements (and adapts) parts of your keyverse server 
// functionality. In particular, it provides functions to read a JSON config, encrypt
// and decrypt data (using AES-128-CBC with OpenSSL), save and retrieve the data,
// and generate GUIDs.
// ----------------------------------------------------------------------------
namespace KeyverseCore {

    std::map<std::string, std::string> readConfig(const std::string& configFilePath) {
        std::ifstream file(configFilePath);
        if (!file) {
            throw std::runtime_error("Failed to open config file for reading");
        }
        json configJson;
        file >> configJson;
        file.close();
        std::map<std::string, std::string> config;
        for (auto it = configJson.begin(); it != configJson.end(); ++it) {
            config[it.key()] = it.value();
        }
        return config;
    }

    std::string generateKey() {
        const int keyLength = 16; // 128 bits
        unsigned char key[keyLength];
        if (RAND_bytes(key, keyLength) != 1) {
            throw std::runtime_error("Failed to generate encryption key");
        }
        return std::string(reinterpret_cast<char*>(key), keyLength);
    }

    std::string encryptData(const std::string& data, const std::string& key) {
        const int blockSize = 16; // AES block size in bytes
        unsigned char iv[blockSize];
        memset(iv, 0, blockSize);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                               reinterpret_cast<const unsigned char*>(key.c_str()), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES encryption");
        }
        int ciphertextLen = 0;
        std::string encryptedData(data.size() + blockSize, '\0');
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&encryptedData[0]),
                              &ciphertextLen, reinterpret_cast<const unsigned char*>(data.c_str()),
                              data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to perform AES encryption");
        }
        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&encryptedData[ciphertextLen]),
                                &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize AES encryption");
        }
        EVP_CIPHER_CTX_free(ctx);
        encryptedData.resize(ciphertextLen + finalLen);
        return encryptedData;
    }

    std::string decryptData(const std::string& encryptedData, const std::string& key) {
        const int blockSize = 16;
        unsigned char iv[blockSize];
        memset(iv, 0, blockSize);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr,
                               reinterpret_cast<const unsigned char*>(key.c_str()), iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES decryption");
        }
        int plaintextLen = 0;
        std::string decryptedData(encryptedData.size(), '\0');
        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&decryptedData[0]),
                              &plaintextLen, reinterpret_cast<const unsigned char*>(encryptedData.c_str()),
                              encryptedData.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to perform AES decryption");
        }
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&decryptedData[plaintextLen]),
                                &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize AES decryption");
        }
        EVP_CIPHER_CTX_free(ctx);
        decryptedData.resize(plaintextLen + finalLen);
        return decryptedData;
    }

    // Save the key–value data: encrypt the JSON dump and write it to two files.
    void saveData(const std::map<std::string, std::string>& keyValues,
                  const std::string& encryptionKey,
                  const std::string& verseFilePath,
                  const std::string& dataFilePath) {
        std::string jsonData = json(keyValues).dump();
        std::string encryptedData = encryptData(jsonData, encryptionKey);

        std::ofstream verseFileOut(verseFilePath, std::ios::binary);
        if (!verseFileOut) {
            throw std::runtime_error("Failed to open verse file for writing");
        }
        verseFileOut.write(encryptedData.c_str(), encryptedData.size());
        verseFileOut.close();

        std::ofstream dataFile(dataFilePath, std::ios::binary);
        if (!dataFile) {
            throw std::runtime_error("Failed to open data file for writing");
        }
        dataFile.write(encryptedData.c_str(), encryptedData.size());
        dataFile.close();

        log("Data saved to " + verseFilePath + " and " + dataFilePath);
    }

    // Retrieve the key–value data from disk by reading, decrypting, and parsing the file.
    std::map<std::string, std::string> retrieveData(const std::string& encryptionKey,
                                                      const std::string& dataFilePath) {
        std::map<std::string, std::string> keyValues;
        std::ifstream file(dataFilePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Failed to open data file for reading");
        }
        std::string encryptedData((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
        file.close();
        std::string decryptedData = decryptData(encryptedData, encryptionKey);
        json jsonData = json::parse(decryptedData);
        for (auto it = jsonData.begin(); it != jsonData.end(); ++it) {
            keyValues[it.key()] = it.value();
        }
        return keyValues;
    }

    // Generate a GUID string.
    std::string generateGUID() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        auto getRandomHexDigit = [&]() {
            int randomInt = dis(gen);
            std::stringstream ss;
            ss << std::hex << randomInt;
            return ss.str();
        };
        std::string guid;
        for (int i = 0; i < 8; ++i) { guid += getRandomHexDigit(); }
        guid += '-';
        for (int i = 0; i < 4; ++i) { guid += getRandomHexDigit(); }
        guid += '-';
        for (int i = 0; i < 4; ++i) { guid += getRandomHexDigit(); }
        guid += '-';
        for (int i = 0; i < 4; ++i) { guid += getRandomHexDigit(); }
        guid += '-';
        for (int i = 0; i < 12; ++i) { guid += getRandomHexDigit(); }
        return guid;
    }

} // namespace KeyverseCore

// ----------------------------------------------------------------------------
// The KeyverseContext structure holds our runtime state (key–value store, file paths,
// and encryption key). We use this to avoid globals and allow multiple independent instances.
// ----------------------------------------------------------------------------
struct KeyverseContext {
    std::map<std::string, std::string> keyValues;
    std::string encryptionKey;
    std::string verseFolderPath;
    std::string verseFilePath;
    std::string dataFilePath;
};

// ----------------------------------------------------------------------------
// Exported API implementation
// ----------------------------------------------------------------------------
extern "C" {

KEYVERSE_API KeyverseContext* kv_create_context(const char* configFilePath) {
    try {
        KeyverseContext* ctx = new KeyverseContext();
        std::map<std::string, std::string> cfg = KeyverseCore::readConfig(configFilePath);
        if (cfg.find("verseFolderPath") == cfg.end()) {
            throw std::runtime_error("Config missing 'verseFolderPath'");
        }
        ctx->verseFolderPath = cfg["verseFolderPath"];
        // Ensure the folder exists (create if necessary)
        std::filesystem::create_directories(ctx->verseFolderPath);
        if (cfg.find("encryptionKey") != cfg.end() && !cfg["encryptionKey"].empty()) {
            ctx->encryptionKey = cfg["encryptionKey"];
        } else {
            ctx->encryptionKey = KeyverseCore::generateKey();
        }
        ctx->verseFilePath = ctx->verseFolderPath + "/data.vs";
        ctx->dataFilePath = ctx->verseFolderPath + "/data.dat";
        // Try to load existing key–value data; if not available, start with an empty store.
        try {
            ctx->keyValues = KeyverseCore::retrieveData(ctx->encryptionKey, ctx->dataFilePath);
        } catch (...) {
            ctx->keyValues = std::map<std::string, std::string>();
        }
        return ctx;
    } catch (...) {
        return nullptr;
    }
}

KEYVERSE_API void kv_destroy_context(KeyverseContext* ctx) {
    if (ctx) {
        delete ctx;
    }
}

KEYVERSE_API int kv_set(KeyverseContext* ctx, const char* key, const char* value) {
    if (!ctx || !key || !value) return -1;
    try {
        ctx->keyValues[key] = value;
        KeyverseCore::saveData(ctx->keyValues, ctx->encryptionKey, ctx->verseFilePath, ctx->dataFilePath);
        return 0;
    } catch (...) {
        return -2;
    }
}

KEYVERSE_API char* kv_get(KeyverseContext* ctx, const char* key) {
    if (!ctx || !key) return nullptr;
    std::string result;
    auto it = ctx->keyValues.find(key);
    if (it != ctx->keyValues.end()) {
        result = it->second;
    } else {
        result = "Key not found.";
    }
    char* ret = new char[result.size() + 1];
    std::strcpy(ret, result.c_str());
    return ret;
}

KEYVERSE_API char* kv_list_all(KeyverseContext* ctx) {
    if (!ctx) return nullptr;
    std::string result;
    for (const auto& kv : ctx->keyValues) {
        result += kv.first + ": " + kv.second + "\n";
    }
    if (result.empty()) {
        result = "No records found.";
    }
    char* ret = new char[result.size() + 1];
    std::strcpy(ret, result.c_str());
    return ret;
}

KEYVERSE_API int kv_save(KeyverseContext* ctx) {
    if (!ctx) return -1;
    try {
        KeyverseCore::saveData(ctx->keyValues, ctx->encryptionKey, ctx->verseFilePath, ctx->dataFilePath);
        return 0;
    } catch (...) {
        return -2;
    }
}

KEYVERSE_API char* kv_backup(KeyverseContext* ctx) {
    if (!ctx) return nullptr;
    try {
        std::string jsonData = json(ctx->keyValues).dump();
        std::string encryptedData = KeyverseCore::encryptData(jsonData, ctx->encryptionKey);
        char* ret = new char[encryptedData.size() + 1];
        std::memcpy(ret, encryptedData.c_str(), encryptedData.size() + 1);
        return ret;
    } catch (...) {
        return nullptr;
    }
}

KEYVERSE_API char* kv_generate_guid(void) {
    try {
        std::string guid = KeyverseCore::generateGUID();
        char* ret = new char[guid.size() + 1];
        std::strcpy(ret, guid.c_str());
        return ret;
    } catch (...) {
        return nullptr;
    }
}

KEYVERSE_API void kv_free_string(char* str) {
    if (str) {
        delete[] str;
    }
}

} // extern "C"

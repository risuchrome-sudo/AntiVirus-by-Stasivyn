#include "stasivyn_api.h"

#include <windows.h>
#include <bcrypt.h>
#include <yara.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <mutex>

#pragma comment(lib, "bcrypt.lib")

namespace {
std::mutex g_lock;
YR_RULES* g_rules = nullptr;
bool g_yara_initialized = false;
std::filesystem::path g_hashes;

void message(wchar_t* out, size_t capacity, const std::wstring& value) {
    if (!out || capacity == 0) return;
    wcsncpy_s(out, capacity, value.c_str(), _TRUNCATE);
}

std::string utf8(const std::filesystem::path& path) {
    std::wstring value = path.wstring();
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr);
    result.resize(result.size() - 1);
    return result;
}

bool sha256(const std::filesystem::path& file, std::string& result) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;
    DWORD object_size = 0, hash_size = 0, bytes = 0;
    std::vector<BYTE> object, digest;
    HANDLE handle = INVALID_HANDLE_VALUE;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) goto done;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &bytes, 0) != 0) goto done;
    if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_size), sizeof(hash_size), &bytes, 0) != 0) goto done;
    object.resize(object_size); digest.resize(hash_size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0) != 0) goto done;
    handle = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) goto done;
    for (;;) {
        BYTE buffer[1024 * 1024]; DWORD read = 0;
        if (!ReadFile(handle, buffer, sizeof(buffer), &read, nullptr)) goto done;
        if (read == 0) break;
        if (BCryptHashData(hash, buffer, read, 0) != 0) goto done;
    }
    if (BCryptFinishHash(hash, digest.data(), hash_size, 0) != 0) goto done;
    { std::ostringstream stream; stream << std::hex << std::setfill('0'); for (BYTE byte : digest) stream << std::setw(2) << static_cast<int>(byte); result = stream.str(); }
    ok = true;
done:
    if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

bool known_hash(const std::string& value) {
    std::ifstream input(g_hashes);
    std::string line;
    while (std::getline(input, line)) {
        auto separator = line.find('|');
        if (separator != std::string::npos) line.resize(separator);
        if (line == value) return true;
    }
    return false;
}

int yara_callback(YR_SCAN_CONTEXT*, int message_code, void* message_data, void* user_data) {
    if (message_code == CALLBACK_MSG_RULE_MATCHING && message_data && user_data) {
        *static_cast<bool*>(user_data) = true;
    }
    return CALLBACK_CONTINUE;
}
}

extern "C" int STASIVYN_CALL stasivyn_initialize(const wchar_t* hash_database, const wchar_t* rules_directory) {
    std::lock_guard guard(g_lock);
    if (g_rules) { yr_rules_destroy(g_rules); g_rules = nullptr; }
    if (g_yara_initialized) { yr_finalize(); g_yara_initialized = false; }
    if (!hash_database || !rules_directory) return -1;
    g_hashes = hash_database;
    if (yr_initialize() != ERROR_SUCCESS) return -2;
    g_yara_initialized = true;
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) { yr_finalize(); g_yara_initialized = false; return -3; }
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(rules_directory)) {
            if (!entry.is_regular_file()) continue;
            auto ext = entry.path().extension().wstring();
            if (ext != L".yar" && ext != L".yara") continue;
            FILE* file = _wfopen(entry.path().c_str(), L"rb");
            if (!file || yr_compiler_add_file(compiler, file, nullptr, utf8(entry.path()).c_str()) != ERROR_SUCCESS) {
                if (file) fclose(file); yr_compiler_destroy(compiler); yr_finalize(); g_yara_initialized = false; return -4;
            }
            fclose(file);
        }
    } catch (...) { yr_compiler_destroy(compiler); yr_finalize(); g_yara_initialized = false; return -5; }
    if (yr_compiler_get_rules(compiler, &g_rules) != ERROR_SUCCESS) { yr_compiler_destroy(compiler); yr_finalize(); g_yara_initialized = false; return -6; }
    yr_compiler_destroy(compiler);
    return 0;
}

extern "C" int STASIVYN_CALL stasivyn_scan_file(const wchar_t* file_path, int* status, wchar_t* out, size_t capacity) {
    std::lock_guard guard(g_lock);
    if (!file_path || !status || !g_rules) { message(out, capacity, L"Engine is not initialized"); return -1; }
    std::string digest;
    if (!sha256(file_path, digest)) { message(out, capacity, L"Could not calculate SHA-256"); return -2; }
    if (known_hash(digest)) { *status = 1; message(out, capacity, L"Known SHA-256 threat"); return 0; }
    bool matched = false;
    int scan_result = yr_rules_scan_file(g_rules, utf8(file_path).c_str(), 0, yara_callback, &matched, 8);
    if (scan_result != ERROR_SUCCESS) { message(out, capacity, L"YARA scan failed"); return -3; }
    *status = matched ? 2 : 0;
    message(out, capacity, matched ? L"YARA rule matched" : L"No known hash or YARA match");
    return 0;
}

extern "C" void STASIVYN_CALL stasivyn_cleanup(void) {
    if (g_rules) { yr_rules_destroy(g_rules); g_rules = nullptr; }
    if (g_yara_initialized) { yr_finalize(); g_yara_initialized = false; }
}

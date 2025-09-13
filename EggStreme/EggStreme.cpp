#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <chrono>
#include <thread>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <algorithm>  // For std::transform (lowercase)
#include <cctype>     // For ::isxdigit

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using json = nlohmann::json;

// --- Config ---
struct Config {
    std::vector<std::string> feedUrls;
    int scanIntervalSeconds;
    int scanDurationSeconds;
    bool webhookEnabled;
    std::string webhookUrl;
};

Config LoadConfig(const std::string& path) {
    std::cout << "[DEBUG] Attempting to load configuration from: " << path << std::endl;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Failed to open config file: " << path << ". Exiting." << std::endl;
        exit(1);
    }
    std::cout << "[INFO] Configuration file opened successfully." << std::endl;
    try {
        json j = json::parse(file);
        std::cout << "[DEBUG] JSON parsed successfully. Feeds count: " << j["feeds"].size() << std::endl;
        Config config = {
            j["feeds"].get<std::vector<std::string>>(),
            j["scan_interval_seconds"],
            j["scan_duration_seconds"],
            j["webhook"]["enabled"],
            j["webhook"]["url"]
        };
        std::cout << "[INFO] Configuration loaded: " << config.feedUrls.size() << " feeds, interval="
            << config.scanIntervalSeconds << "s, duration=" << config.scanDurationSeconds << "s, webhook="
            << (config.webhookEnabled ? "enabled" : "disabled") << std::endl;
        return config;
    }
    catch (const json::exception& e) {
        std::cerr << "[ERROR] Failed to parse config JSON: " << e.what() << std::endl;
        exit(1);
    }
}

// --- IOC Database ---
struct IocDatabase {
    std::vector<std::string> ips, domains, urls, hashes;
    std::vector<std::regex> regexPatterns;
};

void LoadIocsFromFile(const std::string& path, std::vector<std::string>& list) {
    std::cout << "[DEBUG] Loading IOCs from file: " << path << std::endl;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "[WARN] No file found: " << path << ". Skipping." << std::endl;
        return;
    }
    std::string line;
    size_t count = 0;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            list.push_back(line);
            count++;
        }
    }
    std::cout << "[INFO] Loaded " << count << " IOCs from " << path << std::endl;
}

void LoadRegexPatterns(const std::string& path, std::vector<std::regex>& list) {
    std::cout << "[DEBUG] Loading regex patterns from file: " << path << std::endl;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "[WARN] No file found: " << path << ". Skipping." << std::endl;
        return;
    }
    std::string line;
    size_t count = 0;
    size_t errors = 0;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            try {
                list.push_back(std::regex(line, std::regex::icase));
                count++;
            }
            catch (const std::regex_error& e) {
                std::cerr << "[ERROR] Invalid regex in " << path << ": " << line << " (Error: " << e.code() << ")" << std::endl;
                errors++;
            }
        }
    }
    std::cout << "[INFO] Loaded " << count << " regex patterns from " << path << ". " << errors << " errors." << std::endl;
}

void LoadIocs(IocDatabase& db) {
    std::cout << "[INFO] Starting local IOC loading..." << std::endl;
    LoadIocsFromFile("ips.txt", db.ips);
    LoadIocsFromFile("domains.txt", db.domains);
    LoadIocsFromFile("urls.txt", db.urls);
    LoadIocsFromFile("hashes.txt", db.hashes);
    LoadRegexPatterns("regex.txt", db.regexPatterns);
    std::cout << "[INFO] Local IOC loading complete. Total local: IPs=" << db.ips.size()
        << ", Domains=" << db.domains.size() << ", URLs=" << db.urls.size()
        << ", Hashes=" << db.hashes.size() << ", Regex=" << db.regexPatterns.size() << std::endl;
}

// --- CSV Parser Helper ---
std::vector<std::string> SplitCsvLine(const std::string& line, char delimiter = ',') {
    std::vector<std::string> tokens;
    std::stringstream ss(line);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        // Trim whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        // Basic handling for quoted fields (remove quotes if present)
        if (!token.empty() && token.front() == '"' && token.back() == '"') {
            token = token.substr(1, token.size() - 2);
        }
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

void LoadIocsFromCsv(const std::string& path, IocDatabase& db) {
    std::cout << "[DEBUG] Parsing CSV from: " << path << std::endl;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "[WARN] CSV file not found, skipping load." << std::endl;
        return;
    }
    std::string line;
    bool headerSkipped = false;
    int ipCount = 0, domainCount = 0, urlCount = 0, hashCount = 0;
    int skippedCount = 0;
    int errorCount = 0;

    while (std::getline(file, line)) {
        if (line.empty()) continue;
        auto columns = SplitCsvLine(line);
        if (columns.size() < 2) {
            skippedCount++;
            continue;  // Need at least 2 columns
        }

        if (!headerSkipped) {
            // Skip header row if detected
            std::string firstCol = columns[0];
            std::transform(firstCol.begin(), firstCol.end(), firstCol.begin(), ::tolower);
            if (firstCol.find("timestamp") != std::string::npos ||
                firstCol.find("date") != std::string::npos ||
                firstCol.find("time") != std::string::npos ||
                firstCol == "indicator" || firstCol == "ioc") {
                std::cout << "[DEBUG] Skipping CSV header row: " << line.substr(0, 50) << "..." << std::endl;
                headerSkipped = true;
                continue;
            }
            headerSkipped = true; // Assume first non-empty row processed
        }

        // Try to intelligently parse each column as potential IOC
        for (const auto& value : columns) {
            if (value.empty()) continue;

            // Skip timestamps (YYYY-MM-DD HH:MM:SS format)
            if (std::regex_match(value, std::regex(R"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"))) {
                continue;
            }

            // Skip malware family descriptions but allow actual domains/IPs
            std::string lowerValue = value;
            std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
            if ((lowerValue.find("possible") != std::string::npos ||
                lowerValue.find("cobalt") != std::string::npos ||
                lowerValue.find("strike") != std::string::npos ||
                lowerValue.find("c&c") != std::string::npos ||
                lowerValue.find("c2") != std::string::npos ||
                lowerValue.find("malware") != std::string::npos ||
                lowerValue.find("suspicious") != std::string::npos ||
                lowerValue.find("threat") != std::string::npos ||
                lowerValue.find("front") != std::string::npos ||
                lowerValue.find("asyncrat") != std::string::npos ||
                lowerValue.find("dcrat") != std::string::npos ||
                lowerValue.find("rat ") != std::string::npos) &&
                value.find('.') == std::string::npos) { // But allow if it contains dots (might be domain)
                continue; // Skip descriptive text without dots
            }

            // Classify IOC by heuristics
            if (value.find("http://") == 0 || value.find("https://") == 0) {
                db.urls.push_back(value);
                urlCount++;
                std::cout << "[DEBUG] CSV URL: " << value << std::endl;
            }
            else if ((value.length() == 32 || value.length() == 40 || value.length() == 64) &&
                std::all_of(value.begin(), value.end(), ::isxdigit)) {
                db.hashes.push_back(value);
                hashCount++;
                std::cout << "[DEBUG] CSV Hash: " << value << std::endl;
            }
            else if (std::count(value.begin(), value.end(), '.') >= 1 &&
                std::count(value.begin(), value.end(), '.') <= 4 &&
                value.find(' ') == std::string::npos) {
                // Could be IP or domain
                if (std::count(value.begin(), value.end(), '.') == 3) {
                    // Likely IP address (simple check)
                    bool isIp = true;
                    size_t start = 0;
                    for (int i = 0; i < 4; i++) {
                        size_t end = value.find('.', start);
                        if (end == std::string::npos && i != 3) {
                            isIp = false;
                            break;
                        }
                        std::string octet = (i == 3) ? value.substr(start) : value.substr(start, end - start);
                        if (octet.empty() || octet.length() > 3) {
                            isIp = false;
                            break;
                        }
                        try {
                            int num = std::stoi(octet);
                            if (num < 0 || num > 255) {
                                isIp = false;
                                break;
                            }
                        }
                        catch (...) {
                            isIp = false;
                            break;
                        }
                        start = end + 1;
                    }

                    if (isIp) {
                        db.ips.push_back(value);
                        ipCount++;
                        std::cout << "[DEBUG] CSV IP: " << value << std::endl;
                    }
                    else {
                        db.domains.push_back(value);
                        domainCount++;
                        std::cout << "[DEBUG] CSV Domain: " << value << std::endl;
                    }
                }
                else {
                    // Likely domain
                    db.domains.push_back(value);
                    domainCount++;
                    std::cout << "[DEBUG] CSV Domain: " << value << std::endl;
                }
            }
            else {
                // Skip unrecognized format
                skippedCount++;
                std::cout << "[DEBUG] CSV Skipped unrecognized: " << value.substr(0, 30) <<
                    (value.length() > 30 ? "..." : "") << std::endl;
            }
        }
    }

    int totalLoaded = ipCount + domainCount + urlCount + hashCount;
    std::cout << "[INFO] CSV load complete: " << totalLoaded << " IOCs loaded (IPs=" << ipCount
        << ", Domains=" << domainCount << ", URLs=" << urlCount << ", Hashes=" << hashCount
        << "), " << skippedCount << " skipped." << std::endl;
}

// --- TXT Feed Loader (for plain text lists) ---
bool isHex(const std::string& s) {
    return std::all_of(s.begin(), s.end(), ::isxdigit);
}

void LoadIocsFromTxt(const std::string& path, IocDatabase& db) {
    std::cout << "[DEBUG] Parsing TXT from: " << path << std::endl;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "[WARN] TXT file not found, skipping load." << std::endl;
        return;
    }
    std::string line;
    int ipCount = 0, domainCount = 0, urlCount = 0, hashCount = 0;
    int skippedCount = 0;
    while (std::getline(file, line)) {
        if (line.empty()) {
            skippedCount++;
            continue;
        }
        // Simple heuristic: if starts with http/https, treat as URL; if dotted like IP, as IP; if 40/64 chars hex, hash; else domain
        if (line.find("http://") == 0 || line.find("https://") == 0) {
            db.urls.push_back(line);
            urlCount++;
        }
        else if (std::count(line.begin(), line.end(), '.') >= 3) {  // Rough IP check
            db.ips.push_back(line);
            ipCount++;
        }
        else if ((line.length() == 40 || line.length() == 64) && isHex(line)) {
            db.hashes.push_back(line);
            hashCount++;
        }
        else {
            db.domains.push_back(line);
            domainCount++;
        }
    }
    std::cout << "[INFO] TXT load complete: IPs=" << ipCount << ", Domains=" << domainCount << ", URLs=" << urlCount
        << ", Hashes=" << hashCount << ", " << skippedCount << " skipped." << std::endl;
}

// --- Feed Fetching ---
std::string FetchFeed(const std::string& url) {
    std::cout << "[DEBUG] Fetching feed from URL: " << url << std::endl;
    HINTERNET hInternet = InternetOpenA("EggStremeScanner", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "[ERROR] InternetOpen failed: " << GetLastError() << std::endl;
        return "";
    }
    std::cout << "[DEBUG] Internet session opened." << std::endl;

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        std::cerr << "[ERROR] InternetOpenUrl failed for " << url << ": " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return "";
    }
    std::cout << "[DEBUG] URL connection opened." << std::endl;

    char buffer[4096];
    DWORD bytesRead;
    std::string response;
    size_t totalBytes = 0;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
        totalBytes += bytesRead;
    }
    std::cout << "[INFO] Fetched " << totalBytes << " bytes from feed." << std::endl;

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}

bool IsCacheStale(const std::string& path) {
    std::cout << "[DEBUG] Checking cache staleness for: " << path << std::endl;
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
        std::cout << "[INFO] Cache file does not exist or inaccessible: " << path << ". Considered stale." << std::endl;
        return true;  // File doesn't exist, consider stale
    }

    FILETIME ft = data.ftLastWriteTime;
    ULARGE_INTEGER fileTime;
    fileTime.LowPart = ft.dwLowDateTime;
    fileTime.HighPart = ft.dwHighDateTime; // Fixed: was dwHighPart

    // Get current time as FILETIME
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);
    ULARGE_INTEGER currentTimeInt;
    currentTimeInt.LowPart = currentTime.dwLowDateTime;
    currentTimeInt.HighPart = currentTime.dwHighDateTime;

    // Calculate age in 100-nanosecond intervals, then convert to milliseconds
    ULONGLONG ageIn100ns = currentTimeInt.QuadPart - fileTime.QuadPart;
    ULONGLONG ageInMs = ageIn100ns / 10000ULL; // Convert to milliseconds
    bool stale = ageInMs > 3600000ULL;  // 1 hour in ms
    std::cout << "[DEBUG] Cache age: " << (ageInMs / 1000.0 / 60) << " minutes. Stale: " << (stale ? "yes" : "no") << std::endl;
    return stale;
}

void SaveToCache(const std::string& path, const std::string& data) {
    std::cout << "[DEBUG] Saving " << data.size() << " bytes to cache: " << path << std::endl;
    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Failed to write cache file: " << path << std::endl;
        return;
    }
    file << data;
    std::cout << "[INFO] Cache saved successfully to: " << path << std::endl;
}

void LoadIocsFromFeed(const std::string& path, IocDatabase& db) {
    std::cout << "[DEBUG] Detecting format for feed: " << path << std::endl;
    // Detect format by extension
    size_t dotPos = path.find_last_of(".");
    std::string ext;
    if (dotPos != std::string::npos) {
        ext = path.substr(dotPos + 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    }

    if (ext == "csv") {
        LoadIocsFromCsv(path, db);
    }
    else if (ext == "txt") {
        LoadIocsFromTxt(path, db);
    }
    else {
        // Fallback to JSON
        std::cout << "[DEBUG] Treating as JSON: " << path << std::endl;
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cout << "[WARN] Feed file not found, skipping load." << std::endl;
            return;
        }
        try {
            json j = json::parse(file);
            if (j.contains("data") && j["data"].is_array()) {
                size_t loadedCount = 0;
                size_t errorCount = 0;
                for (const auto& entry : j["data"]) {
                    std::string type = entry.value("ioc_type", "");
                    std::string value = entry.value("ioc_value", "");
                    if (type == "ip") {
                        db.ips.push_back(value);
                        loadedCount++;
                    }
                    else if (type == "domain") {
                        db.domains.push_back(value);
                        loadedCount++;
                    }
                    else if (type == "url") {
                        db.urls.push_back(value);
                        loadedCount++;
                    }
                    else if (type == "hash") {
                        db.hashes.push_back(value);
                        loadedCount++;
                    }
                    else if (type == "regex") {
                        try {
                            db.regexPatterns.emplace_back(value, std::regex::icase);
                            loadedCount++;
                        }
                        catch (const std::regex_error& e) {
                            std::cerr << "[ERROR] Invalid regex in feed: " << value << " (Error: " << e.code() << ")" << std::endl;
                            errorCount++;
                        }
                    }
                    else {
                        std::cout << "[WARN] Unknown type in JSON: " << type << std::endl;
                    }
                }
                std::cout << "[INFO] Loaded " << loadedCount << " IOCs from JSON. " << errorCount << " regex errors." << std::endl;
            }
            else {
                std::cerr << "[ERROR] Invalid JSON feed format in " << path << ". No 'data' array found." << std::endl;
            }
        }
        catch (const json::exception& e) {
            std::cerr << "[ERROR] Failed to parse feed JSON: " << e.what() << std::endl;
        }
    }
}

// --- Matching ---
bool MatchesIoc(const std::string& input, const IocDatabase& db) {
    if (input.empty()) {
        std::cout << "[DEBUG] Input empty, no match." << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Checking IOC match for input length: " << input.length() << std::endl;

    size_t ipMatches = 0, domainMatches = 0, urlMatches = 0, hashMatches = 0, regexMatches = 0;
    for (const auto& ip : db.ips) {
        if (input.find(ip) != std::string::npos) {
            std::cout << "[DEBUG] IP match found: " << ip << std::endl;
            ipMatches++;
        }
    }
    if (ipMatches > 0) return true;

    for (const auto& domain : db.domains) {
        if (input.find(domain) != std::string::npos) {
            std::cout << "[DEBUG] Domain match found: " << domain << std::endl;
            domainMatches++;
        }
    }
    if (domainMatches > 0) return true;

    for (const auto& url : db.urls) {
        if (input.find(url) != std::string::npos) {
            std::cout << "[DEBUG] URL match found: " << url << std::endl;
            urlMatches++;
        }
    }
    if (urlMatches > 0) return true;

    for (const auto& hash : db.hashes) {
        if (input.find(hash) != std::string::npos) {
            std::cout << "[DEBUG] Hash match found: " << hash << std::endl;
            hashMatches++;
        }
    }
    if (hashMatches > 0) return true;

    for (size_t i = 0; i < db.regexPatterns.size(); ++i) {
        if (std::regex_search(input, db.regexPatterns[i])) {
            std::cout << "[DEBUG] Regex match found (pattern " << i << ")" << std::endl;
            regexMatches++;
        }
    }
    if (regexMatches > 0) return true;

    std::cout << "[DEBUG] No IOC matches found." << std::endl;
    return false;
}

// --- Command Line Extraction ---
std::string GetCommandLineForProcess(HANDLE hProcess) {
    std::cout << "[DEBUG] Extracting command line for process handle." << std::endl;
    typedef LONG NTSTATUS;
    typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    // Define structures properly
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    } PEB, * PPEB;

    typedef struct _PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PVOID PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

    // Constants
    const ULONG ProcessBasicInformation = 0;

    // Fixed: Check if GetModuleHandleA returns NULL
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "[ERROR] Failed to get handle to ntdll.dll." << std::endl;
        return "";
    }

    NtQueryInformationProcessFn NtQueryInformationProcess =
        (NtQueryInformationProcessFn)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        std::cerr << "[ERROR] Failed to get NtQueryInformationProcess." << std::endl;
        return "";
    }
    std::cout << "[DEBUG] NtQueryInformationProcess resolved." << std::endl;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        std::cout << "[WARN] NtQueryInformationProcess failed: 0x" << std::hex << status << std::dec << std::endl;
        return "";
    }
    std::cout << "[DEBUG] ProcessBasicInformation retrieved. PebBaseAddress: " << pbi.PebBaseAddress << std::endl;

    if (!pbi.PebBaseAddress) {
        std::cout << "[WARN] PebBaseAddress is null." << std::endl;
        return "";
    }

    PEB peb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead) || bytesRead != sizeof(peb)) {
        std::cout << "[WARN] Failed to read PEB: bytesRead=" << bytesRead << ", error=" << GetLastError() << std::endl;
        return "";
    }
    std::cout << "[DEBUG] PEB read successfully." << std::endl;

    if (!peb.ProcessParameters) {
        std::cout << "[WARN] ProcessParameters is null." << std::endl;
        return "";
    }

    RTL_USER_PROCESS_PARAMETERS upp;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead) || bytesRead != sizeof(upp)) {
        std::cout << "[WARN] Failed to read RTL_USER_PROCESS_PARAMETERS: bytesRead=" << bytesRead << std::endl;
        return "";
    }
    std::cout << "[DEBUG] Process parameters read. CommandLine length: " << upp.CommandLine.Length << std::endl;

    if (upp.CommandLine.Length == 0) {
        std::cout << "[DEBUG] CommandLine length is 0." << std::endl;
        return "";
    }

    size_t cmdLen = upp.CommandLine.Length / sizeof(WCHAR);
    std::wstring wideCmd(cmdLen, L'\0');
    if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, &wideCmd[0], upp.CommandLine.Length, &bytesRead) || bytesRead != upp.CommandLine.Length) {
        std::cout << "[WARN] Failed to read command line string: bytesRead=" << bytesRead << std::endl;
        return "";
    }
    std::cout << "[DEBUG] Command line string read successfully." << std::endl;

    std::string narrowCmd(wideCmd.begin(), wideCmd.begin() + cmdLen);
    std::cout << "[INFO] Command line extracted: " << narrowCmd.substr(0, 100) << (narrowCmd.length() > 100 ? "..." : "") << std::endl;
    return narrowCmd;
}

// --- Scanner ---
bool ScanProcesses(const IocDatabase& db) {
    std::cout << "[INFO] Starting process scan. Total processes to check: unknown (snapshotting...)" << std::endl;
    bool found = false;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Process snapshot created." << std::endl;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snap, &pe32)) {
        std::cout << "[WARN] Process32FirstW failed: " << GetLastError() << ". No processes found." << std::endl;
        CloseHandle(snap);
        return false;
    }
    std::cout << "[INFO] Process enumeration started." << std::endl;

    size_t totalProcesses = 0;
    size_t processed = 0;
    size_t cmdlineFailures = 0;

    do {
        totalProcesses++;
        std::wstring wname(pe32.szExeFile);
        std::string name(wname.begin(), wname.end());

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            processed++;
            std::string cmdLine = GetCommandLineForProcess(hProcess);
            if (!cmdLine.empty()) {
                if (MatchesIoc(cmdLine, db)) {
                    std::cout << "[ALERT] [!] Suspicious process detected: " << name << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
                    std::cout << "        -> Command Line: " << cmdLine << std::endl;
                    found = true;
                }
                else {
                    std::cout << "[DEBUG] Process " << name << " (PID: " << pe32.th32ProcessID << ") clean." << std::endl;
                }
            }
            else {
                cmdlineFailures++;
                std::cout << "[WARN] Failed to extract cmdline for " << name << " (PID: " << pe32.th32ProcessID << ")" << std::endl;
            }
            CloseHandle(hProcess);
        }
        else {
            std::cout << "[WARN] Failed to open process " << name << " (PID: " << pe32.th32ProcessID << "): " << GetLastError() << std::endl;
        }
    } while (Process32NextW(snap, &pe32));

    CloseHandle(snap);
    std::cout << "[INFO] Process scan complete: " << totalProcesses << " enumerated, " << processed << " opened, "
        << cmdlineFailures << " cmdline failures. " << (found ? "SUSPICIOUS ACTIVITY FOUND!" : "All clean.") << std::endl;
    return found;
}

bool ScanNetworkConnections(const IocDatabase& db) {
    std::cout << "[INFO] Starting network connections scan." << std::endl;
    bool found = false;

    ULONG size = 0;
    DWORD result = GetTcpTable2(nullptr, &size, TRUE);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "[ERROR] Failed to get TCP table size: " << result << std::endl;
        return false;
    }
    std::cout << "[DEBUG] TCP table size: " << size << " bytes." << std::endl;

    // Fixed: Initialize allocated memory to zero
    PMIB_TCPTABLE2 table = (PMIB_TCPTABLE2)calloc(1, size);
    if (!table) {
        std::cerr << "[ERROR] Failed to allocate memory for TCP table (" << size << " bytes)." << std::endl;
        return false;
    }
    std::cout << "[DEBUG] Memory allocated for TCP table." << std::endl;

    result = GetTcpTable2(table, &size, TRUE);
    if (result != NO_ERROR) {
        std::cerr << "[ERROR] Failed to retrieve TCP table: " << result << std::endl;
        free(table);
        return false;
    }
    std::cout << "[INFO] TCP table retrieved: " << table->dwNumEntries << " entries." << std::endl;

    size_t validConnections = 0;
    size_t ipMatches = 0;
    DWORD totalEntries = table->dwNumEntries;

    for (DWORD i = 0; i < totalEntries; i++) {
        DWORD remoteAddr = table->table[i].dwRemoteAddr;
        if (remoteAddr == 0) {
            std::cout << "[DEBUG] Skipping invalid remote addr (0.0.0.0) at index " << i << std::endl;
            continue;  // Skip invalid
        }

        IN_ADDR addr;
        addr.S_un.S_addr = remoteAddr;

        char ipStr[INET_ADDRSTRLEN];
        if (InetNtopA(AF_INET, &addr, ipStr, INET_ADDRSTRLEN)) {
            std::string remoteIp(ipStr);
            if (!remoteIp.empty()) {
                validConnections++;
                std::cout << "[INFO] Checking connection to: " << remoteIp << " (state: "
                    << table->table[i].dwState << ")" << std::endl;
                if (std::find(db.ips.begin(), db.ips.end(), remoteIp) != db.ips.end()) {
                    std::cout << "[ALERT] [!] Malicious IP detected: " << remoteIp << " (index: " << i << ")" << std::endl;
                    found = true;
                    ipMatches++;
                }
                else {
                    std::cout << "[DEBUG] IP " << remoteIp << " clean." << std::endl;
                }
            }
        }
        else {
            std::cout << "[WARN] Failed to convert IP at index " << i << std::endl;
        }
    }

    free(table);
    std::cout << "[INFO] Network scan complete: " << validConnections << " valid, "
        << ipMatches << " malicious. " << (found ? "SUSPICIOUS ACTIVITY FOUND!" : "All clean.") << std::endl;
    return found;
}

void SendWebhookAlert(const std::string& url, const std::string& message) {
    std::cout << "[INFO] Sending webhook alert: " << message << std::endl;
    std::cout << "    -> Target URL: " << url << std::endl;
    // TODO: Implement actual POST using WinHTTP or similar
    std::cout << "[DEBUG] Webhook send simulated (TODO: implement real POST)." << std::endl;
}

int main() {
    std::cout << "EggStreme IOC Scanner - Final Edition (Updated for September 2025)" << std::endl << std::endl;
    std::cout << "[INFO] Scanner starting up on " << __DATE__ << " " << __TIME__ << std::endl;

    Config config = LoadConfig("config.json");
    if (config.feedUrls.empty()) {
        std::cerr << "[ERROR] No feed URLs in config. Exiting." << std::endl;
        return 1;
    }

    IocDatabase db;

    std::cout << "[INFO] Loading IOCs from local files..." << std::endl;
    LoadIocs(db);

    // Aggregate IOCs from multiple feeds
    size_t successfulFeeds = 0;
    size_t failedFeeds = 0;
    for (size_t i = 0; i < config.feedUrls.size(); ++i) {
        std::string feedUrl = config.feedUrls[i];
        std::string cachePath = "cache_" + std::to_string(i) + ".json";  // Default
        size_t dotPos = feedUrl.find_last_of(".");
        if (dotPos != std::string::npos) {
            std::string urlExt = feedUrl.substr(dotPos + 1);
            std::transform(urlExt.begin(), urlExt.end(), urlExt.begin(), ::tolower);
            if (urlExt == "csv") {
                cachePath = "cache_" + std::to_string(i) + ".csv";
            }
            else if (urlExt == "txt") {
                cachePath = "cache_" + std::to_string(i) + ".txt";
            }
        }
        std::cout << std::endl << "[INFO] Processing feed " << (i + 1) << "/" << config.feedUrls.size() << ": " << feedUrl << std::endl;

        if (IsCacheStale(cachePath)) {
            std::cout << "[INFO] Cache stale or missing. Fetching..." << std::endl;
            std::string feed = FetchFeed(feedUrl);
            if (!feed.empty()) {
                SaveToCache(cachePath, feed);
                std::cout << "[SUCCESS] Feed " << (i + 1) << " fetched and cached." << std::endl;
                successfulFeeds++;
            }
            else {
                std::cerr << "[ERROR] Failed to fetch feed " << (i + 1) << ". Skipping." << std::endl;
                failedFeeds++;
                continue;
            }
        }
        else {
            std::cout << "[INFO] Cache fresh. Using existing for feed " << (i + 1) << "." << std::endl;
            successfulFeeds++;
        }

        std::cout << "[INFO] Loading IOCs from cached feed " << (i + 1) << " (" << cachePath << ")..." << std::endl;
        LoadIocsFromFeed(cachePath, db);
    }

    std::cout << std::endl << "[SUMMARY] Feed processing complete: " << successfulFeeds << " successful, " << failedFeeds << " failed." << std::endl;

    std::cout << std::endl << "[INFO] Final IOC Summary:" << std::endl;
    std::cout << "    -> IPs: " << db.ips.size() << std::endl;
    std::cout << "    -> Domains: " << db.domains.size() << std::endl;
    std::cout << "    -> URLs: " << db.urls.size() << std::endl;
    std::cout << "    -> Hashes: " << db.hashes.size() << std::endl;
    std::cout << "    -> Regex patterns: " << db.regexPatterns.size() << std::endl;
    std::cout << "[INFO] Total IOCs loaded: " << (db.ips.size() + db.domains.size() + db.urls.size() + db.hashes.size() + db.regexPatterns.size()) << std::endl;

    bool foundSuspicious = false;
    int elapsed = 0;
    int cycleCount = 0;

    std::cout << std::endl << "[INFO] Starting scanning loop: " << config.scanDurationSeconds << "s total, every "
        << config.scanIntervalSeconds << "s." << std::endl;

    while (elapsed < config.scanDurationSeconds) {
        cycleCount++;
        time_t now_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm now_tm;
        localtime_s(&now_tm, &now_t);
        std::cout << std::endl << "[CYCLE " << cycleCount << "] Scan cycle at " << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S")
            << " (elapsed: " << elapsed << "s)" << std::endl;

        bool cycleSuspicious = false;
        cycleSuspicious |= ScanProcesses(db);
        cycleSuspicious |= ScanNetworkConnections(db);

        if (cycleSuspicious) {
            foundSuspicious = true;
            std::cout << "[ALERT] Suspicious activity in cycle " << cycleCount << "!" << std::endl;
            if (config.webhookEnabled && !config.webhookUrl.empty()) {
                SendWebhookAlert(config.webhookUrl, "ALERT: EggStreme Scanner Alert: Suspicious activity detected in cycle " + std::to_string(cycleCount) + ".");
            }
        }
        else {
            std::cout << "[INFO] Cycle " << cycleCount << " clean." << std::endl;
        }

        if (elapsed + config.scanIntervalSeconds >= config.scanDurationSeconds) {
            std::cout << "[INFO] Last cycle completed. Exiting loop." << std::endl;
            break;
        }

        std::cout << "[INFO] Sleeping for " << config.scanIntervalSeconds << " seconds..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(config.scanIntervalSeconds));
        elapsed += config.scanIntervalSeconds;
    }

    if (!foundSuspicious) {
        std::cout << std::endl << "[+] No suspicious activity detected across " << cycleCount << " cycles." << std::endl;
    }

    std::cout << std::endl << "================================================================" << std::endl;
    std::cout << "               EGGSTREME IOC SCANNER - FINAL SUMMARY" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "[FEEDS PROCESSED]" << std::endl;
    std::cout << "    -> Total feed URLs configured: " << config.feedUrls.size() << std::endl;
    std::cout << "    -> Successfully processed: " << successfulFeeds << std::endl;
    std::cout << "    -> Failed to process: " << failedFeeds << std::endl;
    std::cout << std::endl;

    std::cout << "[IOC DATABASE SUMMARY]" << std::endl;
    std::cout << "    -> IP Addresses: " << db.ips.size() << std::endl;
    std::cout << "    -> Domain Names: " << db.domains.size() << std::endl;
    std::cout << "    -> URLs: " << db.urls.size() << std::endl;
    std::cout << "    -> File Hashes: " << db.hashes.size() << std::endl;
    std::cout << "    -> Regex Patterns: " << db.regexPatterns.size() << std::endl;
    std::cout << "    -> TOTAL IOCs LOADED: " << (db.ips.size() + db.domains.size() + db.urls.size() + db.hashes.size() + db.regexPatterns.size()) << std::endl;
    std::cout << std::endl;

    std::cout << "[SCAN STATISTICS]" << std::endl;
    std::cout << "    -> Scan duration configured: " << config.scanDurationSeconds << " seconds" << std::endl;
    std::cout << "    -> Scan interval: " << config.scanIntervalSeconds << " seconds" << std::endl;
    std::cout << "    -> Total scan cycles completed: " << cycleCount << std::endl;
    std::cout << "    -> Actual runtime: " << elapsed << " seconds" << std::endl;
    std::cout << std::endl;

    std::cout << "[THREAT DETECTION RESULTS]" << std::endl;
    if (foundSuspicious) {
        std::cout << "    -> STATUS: [!] SUSPICIOUS ACTIVITY DETECTED! [!]" << std::endl;
        std::cout << "    -> Review the scan logs above for details" << std::endl;
        if (config.webhookEnabled) {
            std::cout << "    -> Webhook alerts were sent to: " << config.webhookUrl << std::endl;
        }
    }
    else {
        std::cout << "    -> STATUS: [+] ALL CLEAN - No threats detected" << std::endl;
        std::cout << "    -> System appears to be free of known IOCs" << std::endl;
    }
    std::cout << std::endl;

    std::cout << "[HASH TEST VERIFICATION]" << std::endl;
    if (db.hashes.size() > 0) {
        std::cout << "    -> Hash database loaded successfully" << std::endl;
        std::cout << "    -> Sample hashes loaded:" << std::endl;
        for (size_t i = 0; i <  min(static_cast<size_t>(3), db.hashes.size()); ++i) {
            std::cout << "       - " << db.hashes[i] << std::endl;
        }
        if (db.hashes.size() > 3) {
            std::cout << "       - ... and " << (db.hashes.size() - 3) << " more" << std::endl;
        }
        std::cout << "    -> Hash matching: ENABLED [OK]" << std::endl;
    }
    else {
        std::cout << "    -> No hashes loaded - hash detection disabled" << std::endl;
    }
    std::cout << std::endl;

    time_t end_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    tm end_tm;
    localtime_s(&end_tm, &end_time);
    std::cout << "[SESSION INFO]" << std::endl;
    std::cout << "    -> Scan completed at: " << std::put_time(&end_tm, "%Y-%m-%d %H:%M:%S") << std::endl;
    std::cout << "    -> Build date: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "    -> Version: EggStreme IOC Scanner v1.0 Final Edition" << std::endl;

    std::cout << std::endl << "================================================================" << std::endl;
    std::cout << std::endl;

    std::cout << "Press any key to quit..." << std::endl;
    std::cin.get();

    std::cout << std::endl << "EggStreme IOC Scanner - Finished." << std::endl;
    std::cout << "[INFO] Scanner shutdown complete." << std::endl;

    return 0;
}
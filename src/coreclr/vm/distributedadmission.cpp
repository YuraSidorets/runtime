#include "distributedadmission.h"
#include "distributedevidence.h"
#include "distributedidentity.h"
#include "distributedthreadterminal.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <limits.h>
#include <unistd.h>

extern char** environ;
extern "C" int64_t DistributedControlNative(int command, int argument,
    unsigned char* buffer, int length);

namespace
{
constexpr size_t kManifestLimit = 262144;
constexpr size_t kFileLimit = 512;
constexpr uint64_t kFileBytesLimit = 1024ULL * 1024 * 1024;
constexpr size_t kTransportBuffer = 16 + 4096;
constexpr size_t kMessageSize = 72;
constexpr size_t kPendingRecordLimit = 512;
constexpr int kStartTransport = 0;
constexpr int kEnqueue = 1;
constexpr int kReceive = 2;
constexpr int kStat = 3;
constexpr int kStopTransport = 4;
constexpr int kAbort = 5;
constexpr int kKindReadyGrant = 16;
constexpr int kKindAck = 17;
constexpr int kKindEvidenceBatch = 18;
constexpr int kKindTerminalPrepare = 19;
constexpr int kKindCustodyReceipt = 20;
constexpr int kKindTerminalAck = 21;
constexpr int kTransportReady = 2;
constexpr int kTransportAborted = 3;
constexpr int kTransportStopped = 4;
constexpr int kNodeCoordinator = 1;
constexpr int kNodeWorker = 2;
constexpr int kPhaseReady = 1;
constexpr int kPhaseGrant = 2;
constexpr int kPhaseStagedAck = 3;

enum class Role { None, Coordinator, Worker };
enum class State { Empty, Prepared, Matched, Barrier, Authorized, Consumed, WorkerStaged, Rejected, Stopped };
enum class Category { Core, App, Tls };

struct Identity
{
    std::string runHex;
    std::string manifestHex;
    std::string cpuHex;
    std::string appBasename;
    unsigned char run[16]{};
    unsigned char manifest[32]{};
    unsigned char buildManifest[32]{}; // Positive Thread profile: authenticated run-manifest field.
    unsigned char localInc[16]{};
    unsigned char peerInc[16]{};
    unsigned char localPin[32]{};
    unsigned char peerPin[32]{};
    unsigned char member1Inc[16]{};
    unsigned char member2Inc[16]{};
    unsigned char member1Pin[32]{};
    unsigned char member2Pin[32]{};
    unsigned char mvid[16]{};
    unsigned typeToken = 0;
    unsigned methodToken = 0;
    unsigned char sigHash[32]{};
    unsigned char ilHash[32]{};
    std::string coreRoot;
    std::string appRoot;
    std::string sslPath;
    std::string cryptoPath;
    int localId = 0;
    int peerId = 0;
    Role role = Role::None;
    bool emptyProbe = false;
    bool identityProbe = false;
    bool accessProbe = false;
    bool publicationProbe = false;
    bool threadProbe = false;
    bool threadNegativeProbe = false;
    unsigned char topology[32]{};
};

struct FileRecord
{
    Category category;
    std::string basename;
    std::string path;
    uint64_t bytes;
    unsigned char hash[32];
    dev_t device;
    ino_t inode;
    struct timespec modified;
    struct timespec changed;
};

bool SameStat(const struct stat& a, const struct stat& b);

std::mutex g_prepareMutex;
Identity g_identity;
std::vector<FileRecord> g_files;
// First CorHost2::Start seals mode: 0 unseen, 1 standalone, 2 admission.
std::atomic<int> g_startMode{0};
std::atomic<bool> g_enabled{false};
std::atomic<bool> g_requested{false};
std::atomic<bool> g_prepared{false};
std::atomic<bool> g_stopping{false};
std::atomic<int> g_state{static_cast<int>(State::Empty)};
std::atomic<bool> g_mainConsumed{false};
std::string g_manifestPath;
bool g_entryConfirmed = false;
bool g_retiredSuccessfully = false;
std::atomic<bool> g_terminalPublished{false};

void Log(const char* phase, int node)
{
    std::fprintf(stderr, "DC_ADMISSION phase=%s node=%d\n", phase, node);
    std::fflush(stderr);
}

int Fail(const char* phase)
{
    DistributedThreadTerminalFailure(static_cast<unsigned>(DCG01Terminal::Origin::Admission), 0, phase);
    int state = g_state.load(std::memory_order_acquire);
    while (state != static_cast<int>(State::Rejected) && state != static_cast<int>(State::Stopped))
    {
        if (g_state.compare_exchange_weak(state, static_cast<int>(State::Rejected), std::memory_order_acq_rel))
        {
            Log(phase, g_identity.localId);
            DistributedEvidenceAbort(1);
            if (g_enabled.load(std::memory_order_acquire) &&
                DistributedControlNative(kStat, 0, nullptr, 0) == kTransportReady)
                DistributedControlNative(kAbort, 0, nullptr, 0);
            break;
        }
    }
    return -1;
}

bool FailBool(const char* phase)
{
    Fail(phase);
    return false;
}

bool IsHexLower(const std::string& value, size_t bytes)
{
    if (value.size() != bytes * 2) return false;
    for (char c : value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool ParseHex(const std::string& value, unsigned char* out, size_t bytes)
{
    if (!out || !IsHexLower(value, bytes)) return false;
    for (size_t i = 0; i < bytes; ++i)
    {
        auto digit = [](char c) -> unsigned { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i] = static_cast<unsigned char>((digit(value[2 * i]) << 4) | digit(value[2 * i + 1]));
    }
    return true;
}

bool ParseHex32(const std::string& value, unsigned& out)
{
    if (!IsHexLower(value, 4)) return false;
    out = 0;
    for (char c : value)
    {
        const unsigned v = c <= '9' ? static_cast<unsigned>(c - '0') : static_cast<unsigned>(c - 'a' + 10);
        out = (out << 4) | v;
    }
    return true;
}

std::string Hex(const unsigned char* bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    std::string result(length * 2, '0');
    for (size_t i = 0; i < length; ++i)
    {
        result[2 * i] = digits[bytes[i] >> 4];
        result[2 * i + 1] = digits[bytes[i] & 15];
    }
    return result;
}

bool Digest(const unsigned char* bytes, size_t length, unsigned char out[32])
{
    if ((!bytes && length != 0) || !out) return false;
    unsigned int outLength = 0;
    return EVP_Digest(bytes, length, out, &outLength, EVP_sha256(), nullptr) == 1 && outLength == 32;
}

bool DigestFd(int fd, unsigned char out[32], uint64_t expectedBytes, struct stat* finalStat)
{
    struct stat before{};
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 ||
        static_cast<uint64_t>(before.st_size) != expectedBytes || expectedBytes > kFileBytesLimit)
        return false;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) return false;
    bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1;
    unsigned char buffer[64 * 1024];
    uint64_t total = 0;
    while (ok)
    {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        total += static_cast<uint64_t>(n);
        ok = total <= expectedBytes && EVP_DigestUpdate(context, buffer, static_cast<size_t>(n)) == 1;
    }
    unsigned int digestLength = 0;
    if (ok) ok = total == expectedBytes && EVP_DigestFinal_ex(context, out, &digestLength) == 1 && digestLength == 32;
    EVP_MD_CTX_free(context);

    struct stat after{};
    if (fstat(fd, &after) != 0 || !SameStat(before, after)) ok = false;
    if (finalStat) *finalStat = after;
    return ok;
}

bool SameStat(const struct stat& a, const struct stat& b)
{
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

bool IsAbsolutePath(const std::string& path)
{
    if (path.empty() || path[0] != '/') return false;
    std::istringstream parts(path);
    std::string part;
    while (std::getline(parts, part, '/'))
        if (part == "." || part == "..") return false;
    return true;
}

bool IsBasename(const std::string& name)
{
    if (name.empty() || name.size() > 255 || name == "." || name == "..") return false;
    for (unsigned char c : name)
        if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) return false;
    return name.find('/') == std::string::npos;
}

bool CanonicalPath(const std::string& source, std::string& result)
{
    if (!IsAbsolutePath(source)) return false;
    char resolved[PATH_MAX];
    if (!realpath(source.c_str(), resolved)) return false;
    result = resolved;
    return true;
}

bool ModulePath(const void* symbol, std::string& result)
{
    Dl_info info{};
    if (!symbol || dladdr(symbol, &info) == 0 || !info.dli_fname || !*info.dli_fname) return false;
    return CanonicalPath(info.dli_fname, result);
}

std::string Directory(const std::string& path)
{
    const size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return std::string();
    return slash == 0 ? "/" : path.substr(0, slash);
}

bool ReadManifest(const std::string& path, std::string& contents)
{
    if (!IsAbsolutePath(path)) return false;
    struct stat linkStat{};
    if (lstat(path.c_str(), &linkStat) != 0 || !S_ISREG(linkStat.st_mode) ||
        linkStat.st_size <= 0 || static_cast<uint64_t>(linkStat.st_size) > kManifestLimit)
        return false;
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat before{};
    bool ok = fstat(fd, &before) == 0 && S_ISREG(before.st_mode) && before.st_size == linkStat.st_size;
    contents.clear();
    if (ok) contents.resize(static_cast<size_t>(before.st_size));
    size_t offset = 0;
    while (ok && offset < contents.size())
    {
        ssize_t n = read(fd, &contents[offset], contents.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        offset += static_cast<size_t>(n);
    }
    struct stat after{};
    if (fstat(fd, &after) != 0 || !SameStat(before, after)) ok = false;
    close(fd);
    return ok && offset == contents.size() && !contents.empty() && contents.back() == '\n';
}

bool SplitLine(const std::string& line, std::vector<std::string>& tokens)
{
    tokens.clear();
    if (line.empty() || line.front() == ' ' || line.back() == ' ') return false;
    for (unsigned char c : line)
        if (c < 0x20 || c > 0x7e) return false;
    size_t start = 0;
    while (start < line.size())
    {
        size_t end = line.find(' ', start);
        if (end == std::string::npos) end = line.size();
        if (end == start) return false;
        tokens.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    return !tokens.empty();
}

bool ParseUnsigned(const std::string& text, uint64_t limit, uint64_t& value)
{
    if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
    value = 0;
    for (char c : text)
    {
        if (c < '0' || c > '9') return false;
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (digit > limit || value > (limit - digit) / 10) return false;
        value = value * 10 + digit;
    }
    return true;
}

bool ParseRoleId(const char* value, int& id)
{
    if (!value || (std::strcmp(value, "1") != 0 && std::strcmp(value, "2") != 0)) return false;
    id = value[0] - '0';
    return true;
}

std::string RequiredEnv(const char* name)
{
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

bool EnvIsClosed(bool profileKnown)
{
    const char* const permitted[] = {
        "COMPlus_ReadyToRun", "COMPlus_TieredCompilation", "COMPlus_TieredPGO", "COMPlus_EnableHWIntrinsic"
    };
    // Before manifest parsing, admit only either exact diagnostic method set. After
    // parsing, require the selected profile's set before any application entry.
    const char* const publicationMethods = "Program:AccessOperations Program:Main Program:WaitForValue";
    const char* const threadMethods = "Node:Worker Program:Main Program:WaitForValue Program:Fail";
    const char* const threadNegativeMethods = "Node:Worker Program:Main";
    const char* const accessMethods =
        "Program:AccessOperations Program:Main Program:ReadArray Program:ReadNullReceiver "
        "Program:RunExceptionOrderCase Program:RunHistoryExhaustionCase "
        "Program:TryUnregisteredReferenceWrite Program:WaitForValue "
        "Program:WriteArray Program:WriteNullReceiver";
    for (char** item = environ; item && *item; ++item)
    {
        const char* equal = std::strchr(*item, '=');
        if (!equal || equal[1] == '\0') continue;
        const size_t keyLength = static_cast<size_t>(equal - *item);
        const char* value = equal + 1;
        if (keyLength >= 8 && std::strncmp(*item, "COMPlus_", 8) == 0)
        {
            bool allowed = false;
            for (const char* name : permitted)
                if (keyLength == std::strlen(name) && std::memcmp(*item, name, keyLength) == 0 &&
                    std::strcmp(value, "0") == 0) allowed = true;
            // Read-only code-generation diagnostics for the exact fixture methods.
            if (keyLength == 17 && std::memcmp(*item, "COMPlus_JitDisasm", 17) == 0)
            {
                if (profileKnown)
                    allowed = std::strcmp(value, g_identity.threadNegativeProbe ? threadNegativeMethods :
                        (g_identity.threadProbe ? threadMethods :
                        (g_identity.publicationProbe ? publicationMethods : accessMethods))) == 0;
                else
                    allowed = std::strcmp(value, publicationMethods) == 0 ||
                        std::strcmp(value, accessMethods) == 0 || std::strcmp(value, threadMethods) == 0 ||
                        std::strcmp(value, threadNegativeMethods) == 0;
            }
            if (!allowed) return false;
        }
        if ((keyLength >= 7 && std::strncmp(*item, "DOTNET_", 7) == 0) ||
            (keyLength >= 8 && std::strncmp(*item, "CORECLR_", 8) == 0)) return false;
        for (const char* name : {"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"})
            if (keyLength == std::strlen(name) && std::memcmp(*item, name, keyLength) == 0) return false;
    }
    for (const char* name : permitted)
    {
        const char* value = std::getenv(name);
        if (!value || std::strcmp(value, "0") != 0) return false;
    }
    return true;
}

bool CpuFingerprint(std::string& fingerprint)
{
    struct utsname system{};
    if (uname(&system) != 0 || std::strcmp(system.sysname, "Linux") != 0 ||
        std::strcmp(system.machine, "x86_64") != 0 || sizeof(void*) != 8) return false;
    const uint16_t endian = 1;
    if (*reinterpret_cast<const unsigned char*>(&endian) != 1) return false;

    std::ifstream input("/proc/cpuinfo");
    if (!input) return false;
    std::string line, agreed;
    bool found = false, sse2 = false, cx16 = false;
    while (std::getline(input, line))
    {
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        const std::string key = line.substr(0, colon);
        const size_t first = key.find_first_not_of(" \t");
        const size_t last = key.find_last_not_of(" \t");
        if (first == std::string::npos || key.substr(first, last - first + 1) != "flags") continue;
        std::istringstream flagStream(line.substr(colon + 1));
        std::string flag, normalized;
        while (flagStream >> flag)
        {
            if (!normalized.empty()) normalized.push_back(' ');
            normalized += flag;
            if (flag == "sse2") sse2 = true;
            if (flag == "cx16") cx16 = true;
        }
        if (!found) { agreed = normalized; found = true; }
        else if (agreed != normalized) return false;
    }
    if (!found || !sse2 || !cx16) return false;
    unsigned char digest[32];
    if (!Digest(reinterpret_cast<const unsigned char*>(agreed.data()), agreed.size(), digest)) return false;
    fingerprint = Hex(digest, sizeof(digest));
    return true;
}

bool LocalCertificatePin(const std::string& path, unsigned char pin[32])
{
    if (!IsAbsolutePath(path)) return false;
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) return false;
    X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!certificate) return false;
    unsigned int length = 0;
    const bool ok = X509_digest(certificate, EVP_sha256(), pin, &length) == 1 && length == 32;
    X509_free(certificate);
    return ok;
}

bool FileIdentity(Category category, const std::string& basename, const std::string& path,
    uint64_t bytes, const unsigned char expectedHash[32], FileRecord& output)
{
    if (!IsBasename(basename) || !IsAbsolutePath(path)) return false;
    const std::string root = Directory(path);
    const std::string actualBase = path.substr(root == "/" ? 1 : root.size() + 1);
    if (actualBase != basename) return false;
    int dir = open(root.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (dir < 0) return false;
    const int fd = openat(dir, basename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dir);
    if (fd < 0) return false;
    unsigned char actual[32];
    struct stat finalStat{};
    const bool ok = DigestFd(fd, actual, bytes, &finalStat) && std::memcmp(actual, expectedHash, 32) == 0;
    close(fd);
    if (!ok) return false;
    output.category = category;
    output.basename = basename;
    output.path = path;
    output.bytes = bytes;
    std::memcpy(output.hash, actual, sizeof(actual));
    output.device = finalStat.st_dev;
    output.inode = finalStat.st_ino;
    output.modified = finalStat.st_mtim;
    output.changed = finalStat.st_ctim;
    return true;
}

const FileRecord* FindFile(Category category, const std::string& basename)
{
    for (const FileRecord& file : g_files)
        if (file.category == category && file.basename == basename) return &file;
    return nullptr;
}

bool SameCategoryPath(const std::string& path, const std::string& root)
{
    return path.size() > root.size() && path.compare(0, root.size(), root) == 0 &&
        (root == "/" || path[root.size()] == '/');
}

bool HasSuffix(const std::string& value, const char* suffix)
{
    const size_t n = std::strlen(suffix);
    return value.size() >= n && value.compare(value.size() - n, n, suffix) == 0;
}

bool DecodeMapsPath(std::string& path)
{
    for (size_t i = 0; i < path.size(); ++i)
    {
        if (path[i] != '\\') continue;
        if (i + 3 >= path.size() || path[i + 1] < '0' || path[i + 1] > '7' ||
            path[i + 2] < '0' || path[i + 2] > '7' || path[i + 3] < '0' || path[i + 3] > '7') return false;
        const char value = static_cast<char>((path[i + 1] - '0') * 64 + (path[i + 2] - '0') * 8 + (path[i + 3] - '0'));
        path.replace(i, 4, 1, value);
    }
    return true;
}

bool ParseMapLine(const std::string& line, std::string& path, dev_t& device, ino_t& inode)
{
    std::istringstream stream(line);
    std::string address, permissions, offset, dev, inodeText;
    if (!(stream >> address >> permissions >> offset >> dev >> inodeText)) return false;
    std::getline(stream, path);
    const size_t firstPathChar = path.find_first_not_of(' ');
    if (firstPathChar == std::string::npos) path.clear();
    else if (firstPathChar > 0) path.erase(0, firstPathChar);
    const size_t dash = address.find('-');
    const size_t colon = dev.find(':');
    if (dash == std::string::npos || colon == std::string::npos) return false;
    const std::string majorText = dev.substr(0, colon);
    const std::string minorText = dev.substr(colon + 1);
    char* end = nullptr;
    const unsigned long majorValue = std::strtoul(majorText.c_str(), &end, 16);
    if (!end || *end) return false;
    const unsigned long minorValue = std::strtoul(minorText.c_str(), &end, 16);
    if (!end || *end) return false;
    const unsigned long long inodeValue = std::strtoull(inodeText.c_str(), &end, 10);
    if (!end || *end) return false;
    device = makedev(majorValue, minorValue);
    inode = static_cast<ino_t>(inodeValue);
    return DecodeMapsPath(path);
}

bool CheckBootstrapMaps()
{
    std::string coreModule;
    if (!ModulePath(reinterpret_cast<const void*>(&DistributedAdmissionPrepare), coreModule)) return false;
    const std::string coreRoot = Directory(coreModule);
    std::ifstream maps("/proc/self/maps");
    if (!maps) return false;
    std::string line;
    while (std::getline(maps, line))
    {
        std::string path;
        dev_t device{};
        ino_t inode{};
        if (!ParseMapLine(line, path, device, inode) || path.empty() || path[0] != '/') continue;
        if (HasSuffix(path, " (deleted)"))
        {
            const std::string mappedPath = path.substr(0, path.size() - std::strlen(" (deleted)"));
            if (HasSuffix(mappedPath, ".dll") || SameCategoryPath(mappedPath, coreRoot)) return false;
            continue;
        }
        if (HasSuffix(path, ".dll"))
        {
            const std::string base = path.substr(path.find_last_of('/') + 1);
            if (base != "System.Private.CoreLib.dll" || Directory(path) != coreRoot) return false;
        }
    }
    return true;
}

bool CheckPreparedMaps()
{
    struct stat exeStat{};
    char exePathBuffer[PATH_MAX];
    const ssize_t exeLength = readlink("/proc/self/exe", exePathBuffer, sizeof(exePathBuffer) - 1);
    if (exeLength <= 0 || static_cast<size_t>(exeLength) >= sizeof(exePathBuffer) - 1) return false;
    exePathBuffer[exeLength] = '\0';
    std::string exePath;
    if (!CanonicalPath(exePathBuffer, exePath) || stat(exePath.c_str(), &exeStat) != 0) return false;
    const FileRecord* corerun = FindFile(Category::Core, "corerun");
    if (!corerun || exePath != corerun->path || exeStat.st_dev != corerun->device || exeStat.st_ino != corerun->inode) return false;

    for (const FileRecord& file : g_files)
    {
        struct stat current{};
        if (stat(file.path.c_str(), &current) != 0 || !S_ISREG(current.st_mode) ||
            current.st_dev != file.device || current.st_ino != file.inode ||
            static_cast<uint64_t>(current.st_size) != file.bytes ||
            current.st_mtim.tv_sec != file.modified.tv_sec || current.st_mtim.tv_nsec != file.modified.tv_nsec ||
            current.st_ctim.tv_sec != file.changed.tv_sec || current.st_ctim.tv_nsec != file.changed.tv_nsec)
            return false;
    }

    std::ifstream maps("/proc/self/maps");
    if (!maps) return false;
    std::string line;
    while (std::getline(maps, line))
    {
        std::string path;
        dev_t device{};
        ino_t inode{};
        if (!ParseMapLine(line, path, device, inode)) return false;
        if (path.empty() || path[0] != '/') continue;
        if (HasSuffix(path, " (deleted)"))
        {
            const std::string mappedPath = path.substr(0, path.size() - std::strlen(" (deleted)"));
            const std::string mappedBase = mappedPath.substr(mappedPath.find_last_of('/') + 1);
            if (HasSuffix(mappedPath, ".dll") || mappedBase == "libcoreclr.so" || mappedBase == "libclrjit.so" ||
                mappedBase == "libssl.so.3" || mappedBase == "libcrypto.so.3" ||
                SameCategoryPath(mappedPath, g_identity.coreRoot) || SameCategoryPath(mappedPath, g_identity.appRoot) ||
                SameCategoryPath(mappedPath, Directory(g_identity.sslPath)) ||
                SameCategoryPath(mappedPath, Directory(g_identity.cryptoPath))) return false;
            continue;
        }

        Category category;
        bool inScope = false;
        std::string base = path.substr(path.find_last_of('/') + 1);
        if (SameCategoryPath(path, g_identity.coreRoot)) { category = Category::Core; inScope = true; }
        else if (SameCategoryPath(path, g_identity.appRoot)) { category = Category::App; inScope = true; }
        else if (Directory(path) == Directory(g_identity.sslPath) && base == "libssl.so.3") { category = Category::Tls; inScope = true; }
        else if (Directory(path) == Directory(g_identity.cryptoPath) && base == "libcrypto.so.3") { category = Category::Tls; inScope = true; }

        if (base == "libcoreclr.so" || base == "libclrjit.so" || base == "libssl.so.3" || base == "libcrypto.so.3")
        {
            const Category expectedCategory = (base == "libssl.so.3" || base == "libcrypto.so.3") ? Category::Tls : Category::Core;
            const FileRecord* file = FindFile(expectedCategory, base);
            if (!file || file->path != path || file->device != device || file->inode != inode) return false;
        }

        if (HasSuffix(path, ".dll") && !inScope) return false;
        const bool trackedShared = HasSuffix(path, ".so") || path.find(".so.") != std::string::npos;
        if (inScope && (HasSuffix(path, ".dll") || trackedShared || path == corerun->path))
        {
            const FileRecord* file = FindFile(category, base);
            if (!file || file->path != path || file->device != device || file->inode != inode) return false;
        }
    }
    return true;
}

bool FileLine(const std::vector<std::string>& t, FileRecord& output)
{
    if (t.size() != 5 || t[0] != "file" || !IsBasename(t[2])) return false;
    Category category;
    if (t[1] == "C") category = Category::Core;
    else if (t[1] == "A") category = Category::App;
    else if (t[1] == "S") category = Category::Tls;
    else return false;
    uint64_t bytes = 0;
    unsigned char expected[32];
    if (!ParseUnsigned(t[3], kFileBytesLimit, bytes) || bytes == 0 || !ParseHex(t[4], expected, 32)) return false;

    std::string path;
    if (category == Category::Core) path = g_identity.coreRoot + "/" + t[2];
    else if (category == Category::App) path = g_identity.appRoot + "/" + t[2];
    else if (t[2] == "libssl.so.3") path = g_identity.sslPath;
    else if (t[2] == "libcrypto.so.3") path = g_identity.cryptoPath;
    else return false;
    return FileIdentity(category, t[2], path, bytes, expected, output);
}

bool ParseManifest(const std::string& contents, const std::string& expectedHash)
{
    unsigned char digest[32];
    if (!Digest(reinterpret_cast<const unsigned char*>(contents.data()), contents.size(), digest) ||
        Hex(digest, sizeof(digest)) != expectedHash) return false;

    std::vector<std::string> lines;
    size_t start = 0;
    while (start < contents.size())
    {
        const size_t end = contents.find('\n', start);
        if (end == std::string::npos) return false;
        if (end == start) return false;
        lines.push_back(contents.substr(start, end - start));
        start = end + 1;
    }
    size_t index = 0;
    std::vector<std::string> t;
    auto take = [&](std::vector<std::string>& tokens) -> bool {
        return index < lines.size() && SplitLine(lines[index++], tokens);
    };
    if (!take(t) || t != std::vector<std::string>{"DC009", "1"}) return false;
    if (!take(t) || t.size() != 2 || t[0] != "profile") return false;
    if (t[1] == "dc009-admission-linux-x64-v1")
        g_identity.emptyProbe = false;
    else if (t[1] == "dc010-directory-linux-x64-v1")
        g_identity.identityProbe = true;
    else if (t[1] == "dc011-ordered-access-linux-x64-v1")
        g_identity.accessProbe = true;
    else if (t[1] == "dc012-coordinator-publication-linux-x64-v1")
    {
        g_identity.accessProbe = true;
        g_identity.publicationProbe = true;
    }
    else if (t[1] == "dc013-instance-thread-linux-x64-v1")
    {
        g_identity.accessProbe = true;
        g_identity.publicationProbe = true;
        g_identity.threadProbe = true;
    }
    else if (t[1] == "dc013-negative-thread-start-linux-x64-v1")
    {
        g_identity.accessProbe = true;
        g_identity.publicationProbe = true;
        g_identity.threadProbe = true;
        g_identity.threadNegativeProbe = true;
    }
    else if (t[1] == "dc022-empty-terminal-probe-v1")
    {
        g_identity.emptyProbe = true;
        if (!take(t) || t.size() != 2 || t[0] != "topology" || !ParseHex(t[1], g_identity.topology, 32)) return false;
    }
    else return false;
    if (g_identity.threadProbe && !g_identity.threadNegativeProbe)
    {
        if (!take(t) || t.size() != 2 || t[0] != "build_manifest" ||
            !ParseHex(t[1], g_identity.buildManifest, 32) ||
            t[1] == std::string(64, '0')) return false;
    }
    if (!take(t) || t.size() != 2 || t[0] != "run" || !ParseHex(t[1], g_identity.run, 16)) return false;
    g_identity.runHex = t[1];
    if (!take(t) || t.size() != 2 || t[0] != "cpu" || !ParseHex(t[1], digest, 32)) return false;
    g_identity.cpuHex = t[1];
    if (!take(t) || t.size() != 7 || t[0] != "entry" || !IsBasename(t[1]) ||
        !ParseHex(t[2], g_identity.mvid, 16) || !ParseHex32(t[3], g_identity.typeToken) ||
        !ParseHex32(t[4], g_identity.methodToken) || !ParseHex(t[5], g_identity.sigHash, 32) ||
        !ParseHex(t[6], g_identity.ilHash, 32)) return false;
    g_identity.appBasename = t[1];

    if (!take(t) || t.size() != 4 || t[0] != "member" || t[1] != "1" ||
        !ParseHex(t[2], g_identity.member1Inc, 16) || !ParseHex(t[3], g_identity.member1Pin, 32)) return false;
    if (!take(t) || t.size() != 4 || t[0] != "member" || t[1] != "2" ||
        !ParseHex(t[2], g_identity.member2Inc, 16) || !ParseHex(t[3], g_identity.member2Pin, 32)) return false;

    if (!take(t) || t.size() != 2 || t[0] != "files") return false;
    uint64_t count = 0;
    if (!ParseUnsigned(t[1], kFileLimit, count) || count < 7) return false;
    g_files.clear();
    std::string previousKey;
    for (uint64_t i = 0; i < count; ++i)
    {
        if (!take(t)) return false;
        FileRecord file{};
        if (!FileLine(t, file)) return false;
        const std::string key = t[1] + "/" + t[2];
        if (!previousKey.empty() && key <= previousKey) return false;
        previousKey = key;
        for (const FileRecord& existing : g_files)
            if (existing.category == file.category && existing.basename == file.basename) return false;
        g_files.push_back(file);
    }
    if (!take(t) || t != std::vector<std::string>{"end"} || index != lines.size()) return false;

    const FileRecord* entryFile = FindFile(Category::App, g_identity.appBasename);
    if (!entryFile) return false;
    const FileRecord* coreclr = FindFile(Category::Core, "libcoreclr.so");
    const FileRecord* jit = FindFile(Category::Core, "libclrjit.so");
    const FileRecord* corelib = FindFile(Category::Core, "System.Private.CoreLib.dll");
    const FileRecord* corerun = FindFile(Category::Core, "corerun");
    const FileRecord* ssl = FindFile(Category::Tls, "libssl.so.3");
    const FileRecord* crypto = FindFile(Category::Tls, "libcrypto.so.3");
    return coreclr && jit && corelib && corerun && ssl && crypto;
}

bool Configure(const char* absoluteAppPath)
{
    if (!absoluteAppPath || !*absoluteAppPath) return false;
    std::string appPath;
    if (!CanonicalPath(absoluteAppPath, appPath)) return false;
    g_identity.appRoot = Directory(appPath);
    g_identity.appBasename = appPath.substr(g_identity.appRoot == "/" ? 1 : g_identity.appRoot.size() + 1);
    if (!IsBasename(g_identity.appBasename)) return false;
    const std::string requestedAppBasename = g_identity.appBasename;

    std::string coreModule, sslModule, cryptoModule;
    if (!ModulePath(reinterpret_cast<const void*>(&DistributedAdmissionPrepare), coreModule) ||
        !ModulePath(reinterpret_cast<const void*>(&SSL_new), sslModule) ||
        !ModulePath(reinterpret_cast<const void*>(&EVP_DigestInit_ex), cryptoModule)) return false;
    g_identity.coreRoot = Directory(coreModule);
    g_identity.sslPath = sslModule;
    g_identity.cryptoPath = cryptoModule;
    if (g_identity.coreRoot.empty() || Directory(sslModule).empty() || Directory(cryptoModule).empty()) return false;

    struct utsname system{};
    if (uname(&system) != 0 || std::strcmp(system.sysname, "Linux") != 0 || std::strcmp(system.machine, "x86_64") != 0 || sizeof(void*) != 8) return false;
    const std::string manifestPath = RequiredEnv("DC_ADMISSION_MANIFEST");
    if (!IsAbsolutePath(manifestPath)) return false;
    g_manifestPath = manifestPath;
    std::string manifest;
    if (!ReadManifest(manifestPath, manifest)) return false;
    const std::string expectedManifest = RequiredEnv("DC_CONTROL_MANIFEST");
    const std::string expectedRun = RequiredEnv("DC_CONTROL_RUN");
    if (!IsHexLower(expectedManifest, 32) || !IsHexLower(expectedRun, 16) || !ParseManifest(manifest, expectedManifest)) return false;
    if (g_identity.appBasename != requestedAppBasename || g_identity.runHex != expectedRun ||
        !ParseHex(expectedManifest, g_identity.manifest, 32)) return false;

    std::string cpu;
    if (!CpuFingerprint(cpu) || cpu != g_identity.cpuHex || !EnvIsClosed(true)) return false;
    const std::string role = RequiredEnv("DC_CONTROL_ROLE");
    const char* localIdText = std::getenv("DC_CONTROL_LOCAL_ID");
    const char* peerIdText = std::getenv("DC_CONTROL_PEER_ID");
    if (role == "server") g_identity.role = Role::Coordinator;
    else if (role == "client") g_identity.role = Role::Worker;
    else return false;
    if (!ParseRoleId(localIdText, g_identity.localId) || !ParseRoleId(peerIdText, g_identity.peerId) ||
        g_identity.localId == g_identity.peerId) return false;
    if ((g_identity.role == Role::Coordinator && (g_identity.localId != 1 || g_identity.peerId != 2)) ||
        (g_identity.role == Role::Worker && (g_identity.localId != 2 || g_identity.peerId != 1))) return false;

    const std::string localInc = RequiredEnv("DC_CONTROL_LOCAL_INC");
    const std::string peerInc = RequiredEnv("DC_CONTROL_PEER_INC");
    const std::string peerPin = RequiredEnv("DC_CONTROL_PEER_SHA256");
    const unsigned char* expectedLocalInc = g_identity.localId == 1 ? g_identity.member1Inc : g_identity.member2Inc;
    const unsigned char* expectedPeerInc = g_identity.peerId == 1 ? g_identity.member1Inc : g_identity.member2Inc;
    const unsigned char* expectedLocalPin = g_identity.localId == 1 ? g_identity.member1Pin : g_identity.member2Pin;
    const unsigned char* expectedPeerPin = g_identity.peerId == 1 ? g_identity.member1Pin : g_identity.member2Pin;
    unsigned char envLocalInc[16], envPeerInc[16], envPeerPin[32], certPin[32];
    if (!IsHexLower(localInc, 16) || !IsHexLower(peerInc, 16) || !IsHexLower(peerPin, 32) ||
        !ParseHex(localInc, envLocalInc, 16) || !ParseHex(peerInc, envPeerInc, 16) ||
        !ParseHex(peerPin, envPeerPin, 32) || std::memcmp(envLocalInc, expectedLocalInc, 16) != 0 ||
        std::memcmp(envPeerInc, expectedPeerInc, 16) != 0 || std::memcmp(envPeerPin, expectedPeerPin, 32) != 0)
        return false;
    std::memcpy(g_identity.localInc, expectedLocalInc, 16);
    std::memcpy(g_identity.peerInc, expectedPeerInc, 16);
    std::memcpy(g_identity.localPin, expectedLocalPin, 32);
    std::memcpy(g_identity.peerPin, expectedPeerPin, 32);

    const std::string address = RequiredEnv("DC_CONTROL_ADDRESS");
    const std::string port = RequiredEnv("DC_CONTROL_PORT");
    const std::string ca = RequiredEnv("DC_CONTROL_CA");
    const std::string certificate = RequiredEnv("DC_CONTROL_CERT");
    const std::string key = RequiredEnv("DC_CONTROL_KEY");
    in_addr parsedAddress{};
    uint64_t parsedPort = 0;
    if (inet_pton(AF_INET, address.c_str(), &parsedAddress) != 1 || !ParseUnsigned(port, 65535, parsedPort) ||
        parsedPort <= 1024 || !IsAbsolutePath(ca) || !IsAbsolutePath(certificate) || !IsAbsolutePath(key) ||
        !LocalCertificatePin(certificate, certPin) || std::memcmp(certPin, expectedLocalPin, 32) != 0)
        return false;

    const char* recordPath = std::getenv("DC_EVIDENCE_RECORD");
    if (g_identity.emptyProbe)
    {
        if (g_identity.role == Role::Coordinator)
        {
            if (!recordPath || !IsAbsolutePath(recordPath)) return false;
        }
        else if (recordPath != nullptr) return false;
        if (!DistributedEvidenceConfigure(g_identity.run, g_identity.manifest, g_identity.topology,
                1, g_identity.member1Inc, 2, g_identity.member2Inc,
                static_cast<uint32_t>(g_identity.localId), g_identity.localInc,
                recordPath, g_identity.role == Role::Coordinator, true)) return false;
    }
    else if (recordPath != nullptr) return false;

    return CheckBootstrapMaps();
}

bool MakeMessage(unsigned phase, int node, const unsigned char incarnation[16], unsigned char out[kMessageSize])
{
    std::memset(out, 0, kMessageSize);
    std::memcpy(out, "DCA1", 4);
    out[4] = 1;
    out[5] = static_cast<unsigned char>(phase);
    out[6] = static_cast<unsigned char>(node);
    std::memcpy(out + 8, g_identity.run, 16);
    std::memcpy(out + 24, g_identity.manifest, 32);
    std::memcpy(out + 56, incarnation, 16);
    return true;
}

bool ValidateMessage(const unsigned char* message, unsigned phase, int node, const unsigned char incarnation[16])
{
    if (std::memcmp(message, "DCA1", 4) != 0 || message[4] != 1 || message[5] != phase ||
        message[6] != node || message[7] != 0 || std::memcmp(message + 8, g_identity.run, 16) != 0 ||
        std::memcmp(message + 24, g_identity.manifest, 32) != 0 ||
        std::memcmp(message + 56, incarnation, 16) != 0) return false;
    return true;
}

bool SendPhase(unsigned phase, int kind, int node, const unsigned char incarnation[16],
    std::chrono::steady_clock::time_point deadline)
{
    unsigned char message[kMessageSize];
    MakeMessage(phase, node, incarnation, message);
    while (!g_stopping.load(std::memory_order_acquire))
    {
        const int64_t result = DistributedControlNative(kEnqueue, kind, message, sizeof(message));
        if (result == 0) return true;
        if (result < 0 || result != 1 || std::chrono::steady_clock::now() >= deadline) return false;
        if (DistributedControlNative(kStat, 0, nullptr, 0) != kTransportReady) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

enum class ReceiveResult { Empty, Message, Error };
ReceiveResult ReceivePhase(unsigned char message[kMessageSize], int& kind)
{
    unsigned char buffer[kTransportBuffer]{};
    const int64_t result = DistributedControlNative(kReceive, 0, buffer, sizeof(buffer));
    if (result == 0) return ReceiveResult::Empty;
    if (result < 0 || static_cast<uint64_t>(result) != kMessageSize) return ReceiveResult::Error;
    uint64_t wireKind = 0;
    for (unsigned i = 0; i < 8; ++i) wireKind = (wireKind << 8) | buffer[8 + i];
    if (wireKind != kKindReadyGrant && wireKind != kKindAck) return ReceiveResult::Error;
    kind = static_cast<int>(wireKind);
    std::memcpy(message, buffer + 16, kMessageSize);
    return ReceiveResult::Message;
}

bool TransportAlive()
{
    return DistributedControlNative(kStat, 0, nullptr, 0) == kTransportReady;
}

bool AcceptCoordinatorReady(const unsigned char* message, int kind, bool& readySeen);

bool WaitTransportReady(std::chrono::steady_clock::time_point deadline)
{
    bool listeningLogged = false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        const int64_t state = DistributedControlNative(kStat, 0, nullptr, 0);
        if (state == kTransportReady) return true;
        if (state == kTransportAborted || state == kTransportStopped || state < 0) return false;
        if (g_identity.role == Role::Coordinator && !listeningLogged &&
            DistributedControlNative(kStat, 15, nullptr, 0) == 1)
        {
            Log("listening", g_identity.localId);
            listeningLogged = true;
        }
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool WaitUntilStop()
{
    bool duplicateReadySeen = false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        const int64_t state = DistributedControlNative(kStat, 0, nullptr, 0);
        if (state == kTransportAborted || state == kTransportStopped || state < 0) return false;
        unsigned char message[kMessageSize];
        int kind = 0;
        const ReceiveResult result = ReceivePhase(message, kind);
        if (result == ReceiveResult::Error) return false;
        if (result == ReceiveResult::Message)
        {
            if (AcceptCoordinatorReady(message, kind, duplicateReadySeen)) continue;
            if (kind != kKindReadyGrant || !ValidateMessage(message, kPhaseGrant, kNodeCoordinator, g_identity.peerInc)) return false;
            if (!SendPhase(kPhaseStagedAck, kKindAck, kNodeWorker, g_identity.localInc,
                    std::chrono::steady_clock::now() + std::chrono::seconds(10))) return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool FindPeerReady(const unsigned char* message, int kind)
{
    return kind == kKindReadyGrant && ValidateMessage(message, kPhaseReady, kNodeWorker, g_identity.peerInc);
}

bool FindWorkerAck(const unsigned char* message, int kind)
{
    return kind == kKindAck && ValidateMessage(message, kPhaseStagedAck, kNodeWorker, g_identity.peerInc);
}

bool AcceptCoordinatorReady(const unsigned char* message, int kind, bool& readySeen)
{
    if (kind != kKindReadyGrant || !ValidateMessage(message, kPhaseReady, kNodeCoordinator, g_identity.peerInc))
        return false;
    readySeen = true;
    return true;
}

bool IsCoordinatorGrant(const unsigned char* message, int kind, bool readySeen)
{
    return readySeen && kind == kKindReadyGrant &&
        ValidateMessage(message, kPhaseGrant, kNodeCoordinator, g_identity.peerInc);
}

bool CheckPendingCoordinatorRecords()
{
    for (size_t i = 0; i <= kPendingRecordLimit; ++i)
    {
        unsigned char message[kMessageSize];
        int kind = 0;
        const ReceiveResult result = ReceivePhase(message, kind);
        if (result == ReceiveResult::Empty) return true;
        if (result == ReceiveResult::Error ||
            (!FindPeerReady(message, kind) && !FindWorkerAck(message, kind))) return false;
    }
    return false;
}

bool EvidenceRecord(uint16_t kind, uint64_t epoch, const unsigned char* payload = nullptr, uint32_t bytes = 0)
{
    const unsigned char zero[16]{};
    if (!DistributedEvidenceIsConfigured()) return true;
    return DistributedEvidenceRecord(kind, epoch, zero, zero, zero, payload, bytes);
}

void PutLE16(unsigned char* p, uint16_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
void PutLE32(unsigned char* p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (8 * i)); }
void PutLE64(unsigned char* p, uint64_t v) { for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (8 * i)); }
uint16_t GetLE16(const unsigned char* p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
uint32_t GetLE32(const unsigned char* p) { uint32_t v = 0; for (unsigned i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (8 * i); return v; }
uint64_t GetLE64(const unsigned char* p) { uint64_t v = 0; for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i); return v; }

bool SendOpaque(int kind, const unsigned char* bytes, size_t length,
    std::chrono::steady_clock::time_point deadline)
{
    if (!bytes || length == 0 || length > 4096) return false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        const int64_t result = DistributedControlNative(kEnqueue, kind,
            const_cast<unsigned char*>(bytes), static_cast<int>(length));
        if (result == 0) return true;
        if (result < 0 || result != 1 || std::chrono::steady_clock::now() >= deadline || !TransportAlive()) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

enum class OpaqueResult { Empty, Message, Error };
OpaqueResult ReceiveOpaque(unsigned char* bytes, size_t capacity, size_t& length, int& kind)
{
    if (!bytes || capacity < kTransportBuffer) return OpaqueResult::Error;
    const int64_t result = DistributedControlNative(kReceive, 0, bytes, static_cast<int>(capacity));
    if (result == 0) { length = 0; return OpaqueResult::Empty; }
    if (result < 1 || static_cast<uint64_t>(result) + 16 > capacity) return OpaqueResult::Error;
    uint64_t wireKind = 0;
    for (unsigned i = 0; i < 8; ++i) wireKind = (wireKind << 8) | bytes[8 + i];
    if (!((wireKind >= kKindReadyGrant && wireKind <= kKindTerminalAck))) return OpaqueResult::Error;
    kind = static_cast<int>(wireKind);
    std::memmove(bytes, bytes + 16, static_cast<size_t>(result));
    length = static_cast<size_t>(result);
    return OpaqueResult::Message;
}

bool ReceiveExpectedOpaque(int expectedKind, unsigned char* bytes, size_t capacity, size_t& length,
    std::chrono::steady_clock::time_point deadline)
{
    while (!g_stopping.load(std::memory_order_acquire))
    {
        int kind = 0;
        const OpaqueResult result = ReceiveOpaque(bytes, capacity, length, kind);
        if (result == OpaqueResult::Error) return false;
        if (result == OpaqueResult::Message)
        {
            if (kind == kKindReadyGrant || kind == kKindAck)
            {
                bool duplicate = false;
                if (g_identity.role == Role::Coordinator)
                    duplicate = FindPeerReady(bytes, kind) || FindWorkerAck(bytes, kind);
                else
                    duplicate = (kind == kKindReadyGrant &&
                        (ValidateMessage(bytes, kPhaseReady, kNodeCoordinator, g_identity.peerInc) ||
                         ValidateMessage(bytes, kPhaseGrant, kNodeCoordinator, g_identity.peerInc)));
                if (!duplicate) return false;
                continue;
            }
            return kind == expectedKind;
        }
        if (!TransportAlive() || std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool WorkerTerminalExchange()
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    unsigned char message[kTransportBuffer]{};
    size_t length = 0;
    if (!ReceiveExpectedOpaque(kKindTerminalPrepare, message, sizeof(message), length, deadline) ||
        length != 152 || !DistributedEvidenceValidateTerminalPrepare(message, length)) return false;

    unsigned char prepared[24]{};
    PutLE64(prepared, 1);
    PutLE64(prepared + 8, 0);
    if (!EvidenceRecord(DE_WORKER_TERMINAL_COMMIT_PREPARED, 1, prepared, sizeof(prepared))) return false;

    unsigned char eventRecords[32 * 416]{};
    uint64_t lastSequence = 0;
    uint32_t eventCount = 0, recordBytes = 0;
    unsigned char digest[32];
    if (!DistributedEvidenceFreezeWorker(&lastSequence, &eventCount, &recordBytes,
            digest, eventRecords, sizeof(eventRecords)) || eventCount != 5 || lastSequence != 5 ||
        recordBytes == 0 || recordBytes > sizeof(eventRecords)) return false;

    unsigned char batch[4096]{};
    std::memcpy(batch, "DCEB", 4); PutLE16(batch + 4, 1); PutLE16(batch + 6, 128);
    PutLE32(batch + 8, 0); PutLE32(batch + 12, 1); PutLE32(batch + 16, eventCount); PutLE32(batch + 20, 0);
    PutLE64(batch + 24, 1); PutLE64(batch + 32, lastSequence);
    std::memcpy(batch + 40, g_identity.run, 16); std::memcpy(batch + 56, g_identity.manifest, 32);
    PutLE32(batch + 88, recordBytes);
    if (!Digest(eventRecords, recordBytes, batch + 92)) return false;
    PutLE32(batch + 124, 0);
    std::memcpy(batch + 128, eventRecords, recordBytes);
    const size_t batchBytes = 128 + recordBytes;
    if (!SendOpaque(kKindEvidenceBatch, batch, batchBytes, deadline)) return false;

    if (!ReceiveExpectedOpaque(kKindCustodyReceipt, message, sizeof(message), length, deadline) || length != 160 ||
        !DistributedEvidenceWorkerCustodyReceiptMatches(message, length)) return false;
    // Retirement closes the worker's contribution before DCTA can become
    // visible to the coordinator. A failed or uncertain send cannot resume or
    // replay the terminal contribution.
    if (std::chrono::steady_clock::now() >= deadline || !DistributedEvidenceRetireWorker()) return false;
    unsigned char terminalAck[176]{};
    std::memcpy(terminalAck, "DCTA", 4); PutLE16(terminalAck + 4, 1); PutLE16(terminalAck + 6, 176);
    std::memcpy(terminalAck + 8, g_identity.run, 16); std::memcpy(terminalAck + 24, g_identity.manifest, 32);
    PutLE64(terminalAck + 56, 1); PutLE32(terminalAck + 64, 2);
    std::memcpy(terminalAck + 68, g_identity.localInc, 16); PutLE64(terminalAck + 84, lastSequence);
    PutLE32(terminalAck + 92, eventCount); PutLE32(terminalAck + 96, recordBytes);
    std::memcpy(terminalAck + 100, digest, 32);
    if (!Digest(message, length, terminalAck + 132)) return false;
    PutLE32(terminalAck + 164, 0); PutLE64(terminalAck + 168, 0);
    const int64_t beforeSent = DistributedControlNative(kStat, 2, nullptr, 0);
    if (beforeSent < 0 || !SendOpaque(kKindTerminalAck, terminalAck, sizeof(terminalAck), deadline)) return false;
    while (std::chrono::steady_clock::now() < deadline)
    {
        const int64_t sent = DistributedControlNative(kStat, 2, nullptr, 0);
        if (sent > beforeSent) break;
        if (sent < 0 || !TransportAlive()) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    if (std::chrono::steady_clock::now() >= deadline) return false;
    g_retiredSuccessfully = true;
    // Keep only the native retired transport endpoint alive until the coordinator
    // closes it after sealing/publication. This is cleanup, not another vote.
    while (std::chrono::steady_clock::now() < deadline)
    {
        const int64_t transportState = DistributedControlNative(kStat, 0, nullptr, 0);
        if (transportState != kTransportReady)
            return DistributedControlNative(kStat, 1, nullptr, 0) == 12;
        int kind = 0;
        size_t received = 0;
        const OpaqueResult result = ReceiveOpaque(message, sizeof(message), received, kind);
        if (result == OpaqueResult::Error) return false;
        if (result == OpaqueResult::Message)
        {
            bool duplicate = false;
            if ((kind == kKindReadyGrant || kind == kKindAck) && received == kMessageSize)
                duplicate = ValidateMessage(message, kPhaseReady, kNodeCoordinator, g_identity.peerInc) ||
                    ValidateMessage(message, kPhaseGrant, kNodeCoordinator, g_identity.peerInc) ||
                    ValidateMessage(message, kPhaseStagedAck, kNodeCoordinator, g_identity.peerInc);
            else if (kind == kKindTerminalPrepare)
                duplicate = DistributedEvidenceValidateTerminalPrepare(message, received);
            else if (kind == kKindCustodyReceipt)
                duplicate = DistributedEvidenceWorkerCustodyReceiptMatches(message, received);
            if (!duplicate) return false;
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

bool ParseAndStoreWorkerBatch(const unsigned char* batch, size_t bytes,
    unsigned char workerDigest[32], uint32_t& workerEvents, uint32_t& workerBytes)
{
    if (!batch || bytes < 128 || std::memcmp(batch, "DCEB", 4) != 0 || GetLE16(batch + 4) != 1 ||
        GetLE16(batch + 6) != 128 || GetLE32(batch + 8) != 0 || GetLE32(batch + 12) != 1 ||
        GetLE32(batch + 20) != 0 || GetLE64(batch + 24) != 1 || GetLE64(batch + 32) != 5 ||
        std::memcmp(batch + 40, g_identity.run, 16) != 0 ||
        std::memcmp(batch + 56, g_identity.manifest, 32) != 0 || GetLE32(batch + 124) != 0)
        return false;
    workerEvents = GetLE32(batch + 16);
    workerBytes = GetLE32(batch + 88);
    if (workerEvents != 5 || workerBytes != bytes - 128 || workerBytes > 5 * 416) return false;
    unsigned char payloadHash[32];
    if (!Digest(batch + 128, workerBytes, payloadHash) || std::memcmp(payloadHash, batch + 92, 32) != 0)
        return false;
    size_t offset = 0;
    for (uint32_t i = 0; i < workerEvents; ++i)
    {
        if (offset + 160 > workerBytes) return false;
        const size_t eventBytes = GetLE32(batch + 128 + offset);
        if (eventBytes < 160 || eventBytes > 416 || eventBytes > workerBytes - offset ||
            !DistributedEvidenceAcceptWorkerRecord(batch + 128 + offset, eventBytes)) return false;
        offset += eventBytes;
    }
    if (offset != workerBytes) return false;
    if (!Digest(batch + 128, workerBytes, workerDigest)) return false;
    return DistributedEvidenceCoordinatorCustodyReady(5, workerEvents, workerBytes, workerDigest);
}

int CoordinatorTerminalExchange(int32_t resultCode)
{
    if (!DistributedEvidenceIsEmptyProbe() || g_identity.role != Role::Coordinator || !g_entryConfirmed)
        return Fail("terminal-precondition");
    if (resultCode != 0) return Fail("terminal-nonzero-result");
    unsigned char resultBytes[4], resultDigest[32];
    PutLE32(resultBytes, (uint32_t)resultCode);
    if (!Digest(resultBytes, sizeof(resultBytes), resultDigest)) return Fail("terminal-result-hash");
    if (!EvidenceRecord(DE_MAIN_RETURNED, 1, resultBytes, sizeof(resultBytes))) return Fail("terminal-main-return");
    unsigned char commit[60]{};
    PutLE64(commit, 1); PutLE64(commit + 8, 9); PutLE64(commit + 16, 0);
    PutLE32(commit + 24, (uint32_t)resultCode); std::memcpy(commit + 28, resultDigest, 32);
    if (!EvidenceRecord(DE_COORDINATOR_TERMINAL_COMMIT, 1, commit, sizeof(commit))) return Fail("terminal-commit");

    unsigned char prepare[152]{};
    std::memcpy(prepare, "DCTP", 4); PutLE16(prepare + 4, 1); PutLE16(prepare + 6, 152);
    std::memcpy(prepare + 8, g_identity.run, 16); std::memcpy(prepare + 24, g_identity.manifest, 32);
    PutLE64(prepare + 56, 1); PutLE32(prepare + 64, 1); std::memcpy(prepare + 68, g_identity.localInc, 16);
    PutLE32(prepare + 84, 2); std::memcpy(prepare + 88, g_identity.peerInc, 16); PutLE64(prepare + 104, 9);
    PutLE32(prepare + 112, (uint32_t)resultCode); std::memcpy(prepare + 116, resultDigest, 32);
    if (!EvidenceRecord(DE_TERMINAL_PREPARE_SENT, 1, prepare, sizeof(prepare))) return Fail("terminal-prepare-record");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    if (!SendOpaque(kKindTerminalPrepare, prepare, sizeof(prepare), deadline)) return Fail("terminal-prepare-send");

    unsigned char received[kTransportBuffer]{};
    size_t receivedBytes = 0;
    if (!ReceiveExpectedOpaque(kKindEvidenceBatch, received, sizeof(received), receivedBytes, deadline))
        return Fail("terminal-evidence-receive");
    unsigned char exactBatch[kTransportBuffer]{};
    const size_t exactBatchBytes = receivedBytes;
    std::memcpy(exactBatch, received, exactBatchBytes);
    unsigned char workerDigest[32]; uint32_t workerEvents = 0, workerBytes = 0;
    if (!ParseAndStoreWorkerBatch(received, receivedBytes, workerDigest, workerEvents, workerBytes))
        return Fail("terminal-evidence-invalid");

    unsigned char receipt[160]{};
    std::memcpy(receipt, "DCCR", 4); PutLE16(receipt + 4, 1); PutLE16(receipt + 6, 160);
    std::memcpy(receipt + 8, g_identity.run, 16); std::memcpy(receipt + 24, g_identity.manifest, 32);
    PutLE64(receipt + 56, 1); PutLE32(receipt + 64, 1); std::memcpy(receipt + 68, g_identity.localInc, 16);
    PutLE32(receipt + 84, 2); std::memcpy(receipt + 88, g_identity.peerInc, 16);
    PutLE64(receipt + 104, 5); PutLE32(receipt + 112, workerEvents); PutLE32(receipt + 116, workerBytes);
    std::memcpy(receipt + 120, workerDigest, 32);
    if (!SendOpaque(kKindCustodyReceipt, receipt, sizeof(receipt), deadline) ||
        !EvidenceRecord(DE_CUSTODY_RECEIPT_SENT, 1, receipt, sizeof(receipt)))
        return Fail("terminal-custody-send");

    unsigned char exactDcta[176]{};
    size_t ackBytes = 0;
    if (!ReceiveExpectedOpaque(kKindTerminalAck, received, sizeof(received), ackBytes, deadline) || ackBytes != sizeof(exactDcta))
        return Fail("terminal-ack-receive");
    std::memcpy(exactDcta, received, sizeof(exactDcta));
    if (!EvidenceRecord(DE_TERMINAL_ACK_RECEIVED, 1, exactDcta, sizeof(exactDcta)))
        return Fail("terminal-ack-invalid");

    // Drain already-authenticated records before sealing. Only an exact
    // duplicate DCTA is idempotent; all conflicting or unknown records fail.
    for (size_t i = 0; i <= kPendingRecordLimit; ++i)
    {
        int kind = 0; size_t bytes = 0;
        const OpaqueResult next = ReceiveOpaque(received, sizeof(received), bytes, kind);
        if (next == OpaqueResult::Empty) break;
        if (next != OpaqueResult::Message) return Fail("terminal-pending-record");
        if (kind == kKindReadyGrant || kind == kKindAck)
        {
            if (!FindPeerReady(received, kind) && !FindWorkerAck(received, kind))
                return Fail("terminal-pending-control");
            continue;
        }
        if (kind == kKindEvidenceBatch && bytes == exactBatchBytes &&
            std::memcmp(received, exactBatch, exactBatchBytes) == 0) continue;
        if (kind != kKindTerminalAck || bytes != sizeof(exactDcta) ||
            std::memcmp(received, exactDcta, sizeof(exactDcta)) != 0) return Fail("terminal-pending-record");
        if (i == kPendingRecordLimit) return Fail("terminal-pending-overflow");
    }
    if (!TransportAlive()) return Fail("terminal-failure-before-seal");
    if (!DistributedEvidenceCoordinatorSeal(5, workerDigest, resultCode, resultDigest))
        return Fail("terminal-seal");
    if (DistributedControlNative(kStopTransport, 0, nullptr, 0) != 0)
        return Fail("terminal-transport-stop");
    // The join fixes the set of authenticated records received before local
    // shutdown. A malformed/conflicting record still blocks publication even
    // though the terminal cut has already been sealed.
    for (size_t i = 0; i <= kPendingRecordLimit; ++i)
    {
        int kind = 0; size_t bytes = 0;
        const OpaqueResult next = ReceiveOpaque(received, sizeof(received), bytes, kind);
        if (next == OpaqueResult::Empty) break;
        if (next != OpaqueResult::Message) return Fail("terminal-stop-drain");
        if ((kind == kKindReadyGrant || kind == kKindAck) &&
            (FindPeerReady(received, kind) || FindWorkerAck(received, kind))) continue;
        if (kind == kKindEvidenceBatch && bytes == exactBatchBytes &&
            std::memcmp(received, exactBatch, exactBatchBytes) == 0) continue;
        if (kind == kKindCustodyReceipt && bytes == sizeof(receipt) &&
            std::memcmp(received, receipt, sizeof(receipt)) == 0) continue;
        if (kind == kKindTerminalAck && bytes == sizeof(exactDcta) &&
            std::memcmp(received, exactDcta, sizeof(exactDcta)) == 0) continue;
        return Fail("terminal-stop-unexpected-record");
    }
    if (!DistributedEvidenceWriteRecord(3)) return Fail("terminal-record-write");
    return 0;
}
}

extern "C" int DistributedAdmissionPrepare(const char* absoluteAppPath)
{
    std::lock_guard<std::mutex> lock(g_prepareMutex);
    if (g_enabled.load(std::memory_order_acquire)) return Fail("prepare-duplicate");
    const char* manifestEnv = std::getenv("DC_ADMISSION_MANIFEST");
    if (!manifestEnv && !g_requested.load(std::memory_order_acquire)) return 0;
    g_requested.store(true, std::memory_order_release);
    g_enabled.store(true, std::memory_order_release);
    if (g_startMode.load(std::memory_order_acquire) != 2)
        return Fail("prepare-without-bootstrap");
    if (g_state.load(std::memory_order_acquire) != static_cast<int>(State::Empty))
        return Fail("prepare-after-reject");
    if (!manifestEnv) return Fail("prepare-config-missing");
    if (!Configure(absoluteAppPath)) return Fail("prepare-rejected");
    int expectedState = static_cast<int>(State::Empty);
    if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::Prepared), std::memory_order_acq_rel))
        return Fail("prepare-state");
    g_prepared.store(true, std::memory_order_release);
    if (g_identity.emptyProbe && !EvidenceRecord(DE_ADMISSION_PREPARED, 0)) return Fail("evidence-prepare");
    Log("prepared", g_identity.localId);
    return 1;
}

extern "C" bool DistributedAdmissionIsEnabled(void)
{
    if (g_enabled.load(std::memory_order_acquire) || g_requested.load(std::memory_order_acquire)) return true;
    if (std::getenv("DC_ADMISSION_MANIFEST") == nullptr) return false;
    g_requested.store(true, std::memory_order_release);
    return true;
}

extern "C" bool DistributedAdmissionCopyJournalContext(DistributedAdmissionJournalContext* output)
{
    const State state = static_cast<State>(g_state.load(std::memory_order_acquire));
    if (!output || !g_enabled.load(std::memory_order_acquire) ||
        !g_prepared.load(std::memory_order_acquire) || state == State::Empty ||
        state == State::Rejected || state == State::Stopped || g_manifestPath.empty() ||
        g_manifestPath.size() >= sizeof(output->manifestPath))
        return false;
    std::memset(output, 0, sizeof(*output));
    std::memcpy(output->run, g_identity.run, sizeof(output->run));
    std::memcpy(output->manifestSha256, g_identity.manifest, sizeof(output->manifestSha256));
    output->localNode = static_cast<unsigned>(g_identity.localId);
    output->peerNode = static_cast<unsigned>(g_identity.peerId);
    std::memcpy(output->localIncarnation, g_identity.localInc, sizeof(output->localIncarnation));
    std::memcpy(output->peerIncarnation, g_identity.peerInc, sizeof(output->peerIncarnation));
    std::memcpy(output->manifestPath, g_manifestPath.c_str(), g_manifestPath.size() + 1);
    return true;
}

extern "C" bool DistributedAdmissionCopyThreadIdentity(DistributedAdmissionThreadIdentity* output)
{
    const State state = static_cast<State>(g_state.load(std::memory_order_acquire));
    if (!output || !g_enabled.load(std::memory_order_acquire) ||
        !g_prepared.load(std::memory_order_acquire) || g_stopping.load(std::memory_order_acquire) ||
        !g_entryConfirmed || !g_identity.threadProbe || g_identity.threadNegativeProbe ||
        !((state == State::Consumed && g_identity.role == Role::Coordinator && g_identity.localId == 1) ||
          (state == State::WorkerStaged && g_identity.role == Role::Worker && g_identity.localId == 2)))
        return false;
    DistributedAdmissionThreadIdentity captured{};
    std::memcpy(captured.run, g_identity.run, sizeof(captured.run));
    std::memcpy(captured.runManifestSha256, g_identity.manifest, sizeof(captured.runManifestSha256));
    std::memcpy(captured.buildManifestSha256, g_identity.buildManifest, sizeof(captured.buildManifestSha256));
    std::memcpy(captured.memberIncarnations[0], g_identity.member1Inc, 16);
    std::memcpy(captured.memberIncarnations[1], g_identity.member2Inc, 16);
    captured.localNode = static_cast<unsigned>(g_identity.localId);
    *output = captured;
    return true;
}

extern "C" bool DistributedAdmissionCheckEnvironment(void)
{
    const bool requested = DistributedAdmissionIsEnabled();
    const int desired = requested ? 2 : 1;
    int expected = 0;
    if (!g_startMode.compare_exchange_strong(expected, desired, std::memory_order_acq_rel) && expected != desired)
        return FailBool("bootstrap-mode-change");
    if (!requested) return true;
    // Called before EE startup: no allocation, file access, or managed execution.
    const int state = g_state.load(std::memory_order_acquire);
    if (state == static_cast<int>(State::Rejected) || state == static_cast<int>(State::Stopped)) return false;
    return EnvIsClosed(g_prepared.load(std::memory_order_acquire)) || FailBool("bootstrap-policy");
}

extern "C" bool DistributedAdmissionMatchEntry(const unsigned char* flatPe, size_t peLen,
    const unsigned char* mvid16, unsigned typeToken, unsigned methodToken,
    const unsigned char* sig, size_t sigLen, const unsigned char* il, size_t ilLen)
{
    if (!DistributedAdmissionIsEnabled()) return true;
    if (!g_enabled.load(std::memory_order_acquire) || !g_prepared.load(std::memory_order_acquire) ||
        (g_state.load(std::memory_order_acquire) != static_cast<int>(State::Prepared) &&
         g_state.load(std::memory_order_acquire) != static_cast<int>(State::Matched)) ||
        !flatPe || !mvid16 || (!sig && sigLen) || (!il && ilLen) || peLen == 0 || peLen > kFileBytesLimit ||
        sigLen > 65536 || ilLen > 16 * 1024 * 1024 ||
        typeToken != g_identity.typeToken || methodToken != g_identity.methodToken ||
        std::memcmp(mvid16, g_identity.mvid, 16) != 0)
        return FailBool("entry-rejected");

    const FileRecord* entry = FindFile(Category::App, g_identity.appBasename);
    unsigned char peHash[32], sigHash[32], ilHash[32];
    if (!entry || peLen != entry->bytes || !Digest(flatPe, peLen, peHash) ||
        std::memcmp(peHash, entry->hash, 32) != 0 || !Digest(sig, sigLen, sigHash) ||
        !Digest(il, ilLen, ilHash) || std::memcmp(sigHash, g_identity.sigHash, 32) != 0 ||
        std::memcmp(ilHash, g_identity.ilHash, 32) != 0 || !CheckPreparedMaps())
        return FailBool("entry-rejected");
    int expectedState = static_cast<int>(State::Prepared);
    if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::Matched), std::memory_order_acq_rel))
    {
        if (expectedState == static_cast<int>(State::Matched)) return true;
        return FailBool("entry-state");
    }
    Log("entry-matched", g_identity.localId);
    return true;
}

extern "C" bool DistributedAdmissionConfirmEntry(bool emptyProfileProof)
{
    if (!DistributedAdmissionIsEnabled()) { g_entryConfirmed = true; return true; }
    if (!g_prepared.load(std::memory_order_acquire) ||
        g_state.load(std::memory_order_acquire) != static_cast<int>(State::Matched))
        return FailBool("entry-confirm-state");
    if (g_identity.emptyProbe)
    {
        if (!emptyProfileProof) return FailBool("entry-proof-rejected");
        if (!EvidenceRecord(DE_ENTRY_MATCHED, 0)) return FailBool("entry-evidence");
    }
    g_entryConfirmed = true;
    return true;
}

extern "C" bool DistributedAdmissionIsIdentityProbe(void)
{
    return g_identity.identityProbe && g_entryConfirmed;
}

extern "C" bool DistributedAdmissionIsAccessProbe(void)
{
    return g_identity.accessProbe && g_entryConfirmed;
}

extern "C" bool DistributedAdmissionIsPublicationProbe(void)
{
    return g_identity.publicationProbe && g_entryConfirmed;
}

extern "C" bool DistributedAdmissionIsThreadProbe(void)
{
    return g_identity.threadProbe && g_entryConfirmed;
}

extern "C" bool DistributedAdmissionIsThreadNegativeProbe(void)
{
    return g_identity.threadNegativeProbe && g_entryConfirmed;
}

extern "C" bool DistributedAdmissionIdentityContext(DistributedIdentityContext* context)
{
    if (!context || (!DistributedAdmissionIsIdentityProbe() && !DistributedAdmissionIsAccessProbe()) ||
        g_state.load(std::memory_order_acquire) != static_cast<int>(State::Matched))
        return false;
    const FileRecord* entry = FindFile(Category::App, g_identity.appBasename);
    if (!entry) return false;
    std::memcpy(context->run, g_identity.run, 16);
    context->localNode = g_identity.localId;
    context->peerNode = g_identity.peerId;
    std::memcpy(context->localInc, g_identity.localInc, 16);
    std::memcpy(context->peerInc, g_identity.peerInc, 16);
    std::memcpy(context->assemblyHash, entry->hash, 32);
    std::memcpy(context->mvid, g_identity.mvid, 16);
    return true;
}

extern "C" int DistributedAdmissionIdentityWorker(
    int (*processGraph)(const unsigned char*, int, unsigned char*, int))
{
    if (!processGraph || !DistributedAdmissionIsIdentityProbe() ||
        g_identity.role != Role::Worker ||
        g_state.load(std::memory_order_acquire) != static_cast<int>(State::WorkerStaged))
        return Fail("identity-worker-state");
    // This pump runs on the staged CLR thread in preemptive mode. Only the
    // callback enters cooperative mode; transport progress has its own thread.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    bool duplicateReady = false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        if (!TransportAlive()) return Fail("identity-worker-disconnected");
        if (std::chrono::steady_clock::now() >= deadline) return Fail("identity-worker-timeout");
        unsigned char buffer[kTransportBuffer]{}, reply[4096]{};
        const int64_t size = DistributedControlNative(kReceive, 0, buffer, sizeof(buffer));
        if (size < 0 || size > 4096) return Fail("identity-worker-receive");
        if (size != 0)
        {
            uint64_t kind = 0;
            for (unsigned i = 0; i < 8; ++i) kind = (kind << 8) | buffer[8 + i];
            if (size == kMessageSize && kind == kKindReadyGrant)
            {
                if (AcceptCoordinatorReady(buffer + 16, static_cast<int>(kind), duplicateReady)) continue;
                if (!ValidateMessage(buffer + 16, kPhaseGrant, kNodeCoordinator, g_identity.peerInc) ||
                    !SendPhase(kPhaseStagedAck, kKindAck, kNodeWorker, g_identity.localInc, deadline))
                    return Fail("identity-worker-grant");
                continue;
            }
            if (kind != 22) return Fail("identity-worker-kind");
            const int replySize = processGraph(buffer + 16, static_cast<int>(size), reply, sizeof(reply));
            if (replySize <= 0 || replySize > 4096) return Fail("identity-worker-graph");
            for (;;)
            {
                const int64_t sent = DistributedControlNative(kEnqueue, 23, reply, replySize);
                if (sent == 0) break;
                if (sent != 1 || !TransportAlive() || std::chrono::steady_clock::now() >= deadline)
                    return Fail("identity-worker-reply");
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            Log("identity-worker-resolved", g_identity.localId);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return Fail("identity-worker-stopped");
}

extern "C" bool DistributedAdmissionIsEmptyProbe(void)
{
    return DistributedEvidenceIsEmptyProbe();
}

extern "C" bool DistributedAdmissionRecordMainStarted(void)
{
    if (!DistributedAdmissionIsEnabled() || !g_identity.emptyProbe) return true;
    if (g_identity.role != Role::Coordinator || !g_entryConfirmed ||
        !EvidenceRecord(DE_MAIN_STARTED, 0)) return FailBool("main-start-evidence");
    return true;
}

extern "C" int DistributedAdmissionCompleteMain(int32_t resultCode)
{
    if (!DistributedAdmissionIsEnabled() || !g_identity.emptyProbe) return 0;
    const int result = CoordinatorTerminalExchange(resultCode);
    if (result == 0) g_terminalPublished.store(true, std::memory_order_release);
    return result == 0 ? 1 : -1;
}

extern "C" int DistributedAdmissionBarrier(void)
{
    if (!DistributedAdmissionIsEnabled()) return 0;
    if (!g_enabled.load(std::memory_order_acquire) || !g_prepared.load(std::memory_order_acquire) ||
        g_state.load(std::memory_order_acquire) != static_cast<int>(State::Matched) ||
        !g_entryConfirmed || !CheckPreparedMaps()) return Fail("barrier-precondition");

    int expectedState = static_cast<int>(State::Matched);
    if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::Barrier), std::memory_order_acq_rel))
        return Fail("barrier-state");

    if (g_identity.threadProbe && !g_identity.threadNegativeProbe)
    {
        DistributedAdmissionThreadIdentity terminalIdentity{};
        std::memcpy(terminalIdentity.run, g_identity.run, 16);
        std::memcpy(terminalIdentity.runManifestSha256, g_identity.manifest, 32);
        std::memcpy(terminalIdentity.buildManifestSha256, g_identity.buildManifest, 32);
        std::memcpy(terminalIdentity.memberIncarnations[0], g_identity.member1Inc, 16);
        std::memcpy(terminalIdentity.memberIncarnations[1], g_identity.member2Inc, 16);
        terminalIdentity.localNode = static_cast<unsigned>(g_identity.localId);
        if (!DistributedThreadTerminalConfigure(&terminalIdentity)) return Fail("thread-terminal-configure");
    }
    if (DistributedControlNative(kStartTransport, 0, nullptr, 0) != 0)
        return Fail("transport-start");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    if (!WaitTransportReady(deadline)) return Fail("transport-timeout");
    if (!SendPhase(kPhaseReady, kKindReadyGrant, g_identity.localId, g_identity.localInc, deadline))
        return Fail("ready-send");

    if (g_identity.role == Role::Worker)
    {
        bool coordinatorReadySeen = false;
        bool grantSeen = false;
        while (!g_stopping.load(std::memory_order_acquire))
        {
            if (DistributedControlNative(kStat, 0, nullptr, 0) != kTransportReady) return Fail("worker-disconnected");
            if (std::chrono::steady_clock::now() >= deadline) return Fail("worker-timeout");
            unsigned char message[kMessageSize];
            int kind = 0;
            const ReceiveResult result = ReceivePhase(message, kind);
            if (result == ReceiveResult::Error) return Fail("worker-message");
            if (result == ReceiveResult::Message)
            {
                if (AcceptCoordinatorReady(message, kind, coordinatorReadySeen)) continue;
                if (!IsCoordinatorGrant(message, kind, coordinatorReadySeen))
                    return Fail("worker-grant");
                grantSeen = true;
                if (!SendPhase(kPhaseStagedAck, kKindAck, kNodeWorker, g_identity.localInc,
                        std::chrono::steady_clock::now() + std::chrono::seconds(10))) return Fail("worker-ack");
                if (g_identity.emptyProbe &&
                    (!EvidenceRecord(DE_WORKER_STAGED_ACK_SENT, 0) || !EvidenceRecord(DE_WORKER_STAGED, 0)))
                    return Fail("worker-stage-evidence");
                expectedState = static_cast<int>(State::Barrier);
                if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::WorkerStaged), std::memory_order_acq_rel))
                    return Fail("worker-state");
                Log("worker-staged", g_identity.localId);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!grantSeen) return Fail("worker-stopped");
        if (g_identity.accessProbe) return 4; // VM-owned bounded access-test entry; Main stays coordinator-only.
        if (g_identity.identityProbe) return 3; // VM-owned directory pump; never application Main.
        if (g_identity.emptyProbe)
        {
            if (!WorkerTerminalExchange()) return Fail("worker-terminal");
            return 2;
        }
        return WaitUntilStop() ? Fail("worker-unexpected-resume") : Fail("worker-stopped");
    }

    bool readySeen = false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        if (!TransportAlive()) return Fail("coordinator-disconnected");
        if (std::chrono::steady_clock::now() >= deadline) return Fail("coordinator-ready-timeout");
        unsigned char message[kMessageSize];
        int kind = 0;
        const ReceiveResult result = ReceivePhase(message, kind);
        if (result == ReceiveResult::Error) return Fail("coordinator-message");
        if (result == ReceiveResult::Message)
        {
            if (FindPeerReady(message, kind))
            {
                readySeen = true;
                if (g_identity.emptyProbe && !EvidenceRecord(DE_PEER_READY_RECEIVED, 0))
                    return Fail("coordinator-ready-evidence");
            }
            else return Fail("coordinator-peer-ready");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!readySeen) return Fail("coordinator-stopped");

    const auto grantDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    if (!SendPhase(kPhaseGrant, kKindReadyGrant, kNodeCoordinator, g_identity.localInc, grantDeadline))
        return Fail("grant-send");
    if (g_identity.emptyProbe && !EvidenceRecord(DE_GRANT_SENT, 0)) return Fail("grant-evidence");
    bool ackSeen = false;
    while (!g_stopping.load(std::memory_order_acquire))
    {
        if (!TransportAlive()) return Fail("coordinator-disconnected");
        if (std::chrono::steady_clock::now() >= grantDeadline) return Fail("coordinator-ack-timeout");
        unsigned char message[kMessageSize];
        int kind = 0;
        const ReceiveResult result = ReceivePhase(message, kind);
        if (result == ReceiveResult::Error) return Fail("coordinator-message");
        if (result == ReceiveResult::Message)
        {
            if (FindWorkerAck(message, kind))
            {
                ackSeen = true;
                if (g_identity.emptyProbe && !EvidenceRecord(DE_COORDINATOR_STAGED_ACK_RECEIVED, 0))
                    return Fail("coordinator-ack-evidence");
                break;
            }
            if (FindPeerReady(message, kind)) continue;
            return Fail("coordinator-worker-ack");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!ackSeen) return Fail("coordinator-stopped");
    expectedState = static_cast<int>(State::Barrier);
    if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::Authorized), std::memory_order_acq_rel))
        return Fail("coordinator-state");
    Log("coordinator-authorized", g_identity.localId);
    return 1;
}

extern "C" bool DistributedAdmissionConsumeMain(void)
{
    if (!DistributedAdmissionIsEnabled()) return true;
    if (g_mainConsumed.load(std::memory_order_acquire)) return FailBool("main-duplicate");
    if (!g_enabled.load(std::memory_order_acquire) || !g_prepared.load(std::memory_order_acquire) ||
        g_identity.role != Role::Coordinator || g_state.load(std::memory_order_acquire) != static_cast<int>(State::Authorized) ||
        !CheckPreparedMaps() || !TransportAlive()) return FailBool("main-precondition");
    if (!CheckPendingCoordinatorRecords() || !CheckPreparedMaps() || !TransportAlive())
        return FailBool("main-pending-record");
    int expectedState = static_cast<int>(State::Authorized);
    if (!g_state.compare_exchange_strong(expectedState, static_cast<int>(State::Consumed), std::memory_order_acq_rel))
        return FailBool("main-state");
    bool expected = false;
    if (!g_mainConsumed.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return FailBool("main-duplicate");
    if (g_identity.emptyProbe && !EvidenceRecord(DE_MAIN_AUTHORIZATION_CONSUMED, 0))
        return FailBool("main-authorization-evidence");
    Log("main-consumed", g_identity.localId);
    return true;
}

extern "C" bool DistributedAdmissionCheckMaps(void)
{
    if (!DistributedAdmissionIsEnabled()) return true;
    const int state = g_state.load(std::memory_order_acquire);
    if (!g_prepared.load(std::memory_order_acquire)) return state == static_cast<int>(State::Empty) && CheckBootstrapMaps();
    if (state == static_cast<int>(State::Rejected) || state == static_cast<int>(State::Stopped)) return false;
    return CheckPreparedMaps();
}

extern "C" bool DistributedAdmissionCheckCompiler(const void* getJitSymbol)
{
    const int state = g_state.load(std::memory_order_acquire);
    if (!g_prepared.load(std::memory_order_acquire))
        return state == static_cast<int>(State::Empty);
    if (state == static_cast<int>(State::Rejected) || state == static_cast<int>(State::Stopped)) return false;
    if (!getJitSymbol) return FailBool("compiler-symbol");
    std::string compilerPath;
    if (!ModulePath(getJitSymbol, compilerPath)) return FailBool("compiler-module");
    const FileRecord* compiler = FindFile(Category::Core, "libclrjit.so");
    if (!compiler || compilerPath != compiler->path || !CheckPreparedMaps())
        return FailBool("compiler-artifact");
    return true;
}

extern "C" void DistributedAdmissionStop(void)
{
    if (!g_enabled.load(std::memory_order_acquire)) return;
    g_stopping.store(true, std::memory_order_release);
    const int64_t state = DistributedControlNative(kStat, 0, nullptr, 0);
    if (state == kTransportReady && !g_retiredSuccessfully &&
        !g_terminalPublished.load(std::memory_order_acquire))
        DistributedControlNative(kAbort, 0, nullptr, 0);
    DistributedControlNative(kStopTransport, 0, nullptr, 0);
    if (g_identity.emptyProbe && g_identity.role == Role::Coordinator && DistributedEvidenceIsConfigured())
        DistributedEvidenceWriteRecord(1);
    g_state.store(static_cast<int>(State::Stopped), std::memory_order_release);
    Log("stopped", g_identity.localId);
}

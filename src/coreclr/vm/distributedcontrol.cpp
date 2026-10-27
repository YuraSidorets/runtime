// DC-008 research implementation. Linux x64, one fixed peer, one run per process.
// This file intentionally has no CLR/PAL headers or managed callbacks.
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sslerr.h>
#include <openssl/sha.h>
#include "distributedevidence.h"
#include "distributedadmission.h"
#include "distributedthreadterminal.h"
#include "distributedterminalevidence.h"
#include "raw_frame_journal.h"
#include "raw_frame_custody.h"
#include "raw_frame_custody_path.h"
#include <pthread.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <atomic>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace
{
constexpr unsigned Header = 128, Payload = 4096, DataSlots = 4, ControlSlots = 8;
constexpr unsigned FrameSize = Header + Payload;
enum Error { Config = 1, Socket = 2, Deadline = 3, Tls = 4, Identity = 5,
             Envelope = 6, Sequence = 7, Capacity = 8, PeerAbort = 9, LocalAbort = 10,
             Thread = 11, PeerDisconnected = 12 };
struct Item { unsigned kind, length; uint64_t sequence; unsigned char body[Payload]; };
struct Control { unsigned kind; uint64_t correlation, window; };
struct ConfigData
{
    bool server;
    sockaddr_in address;
    unsigned localId, peerId;
    unsigned char run[16], manifest[32], localInc[16], peerInc[16], peerPin[32];
    char ca[512], cert[512], key[512], admissionManifest[512];
};
ConfigData config;
dcg01_raw::Journal g_frameJournal;
DCG01Terminal::FailureOrder g_threadTerminal;
// Only the native transport owner writes/reads this frozen authenticated session.
DCG01Disconnect::Notice disconnectSession;
// ponytail: one fixed peer/run per process; extend only with an admitted membership profile.
std::atomic<uint64_t> stats[20]{};
std::atomic<bool> stop{false}, abortRequested{false};
std::atomic<uint64_t> gcWindow{0}, gcNext{0};
static_assert(ATOMIC_LONG_LOCK_FREE == 2 && ATOMIC_LLONG_LOCK_FREE == 2,
              "GC boundary diagnostics must never acquire a fallback lock");
pthread_mutex_t queueLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t lifecycleLock = PTHREAD_MUTEX_INITIALIZER;
pthread_t worker;
bool created = false;
bool journalPersistenceClaimed = false; // Protected by lifecycleLock; no run reset.
Item tx[DataSlots]{}, rx[DataSlots]{};
unsigned txHead = 0, txCount = 0, rxHead = 0, rxCount = 0;
uint64_t consumed = 0;

uint64_t now()
{
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}
bool unexpectedTlsEof(unsigned long error)
{
    return error != 0 && ERR_GET_LIB(error) == ERR_LIB_SSL &&
        ERR_GET_REASON(error) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
}
void fail(Error e)
{
    g_frameJournal.MarkIncomplete();
    // A prior informational disconnect must never suppress a later fatal fault.
    g_threadTerminal.Fail(DCG01Terminal::Origin::Transport, static_cast<unsigned>(e), nullptr);
    uint64_t expected = 0;
    if (stats[1].compare_exchange_strong(expected, e))
    {
        // The evidence ordering lock linearizes a fatal notice against the
        // coordinator's terminal seal. This callback performs no I/O/wait.
        DistributedEvidenceTransportFailure((uint32_t)e);
    }
    stats[0].store(3);
}
bool captureProcessIdentity(dcg01_raw::SessionContext& session)
{
    session.processId = static_cast<uint64_t>(getpid());
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char statText[4096];
    ssize_t statBytes = read(fd, statText, sizeof(statText) - 1);
    close(fd);
    if (statBytes <= 0 || static_cast<size_t>(statBytes) >= sizeof(statText) - 1) return false;
    statText[statBytes] = '\0';
    char* cursor = strrchr(statText, ')');
    if (!cursor) return false;
    ++cursor;
    // Skip /proc/self/stat fields 3..21; field 22 is process start time in ticks.
    for (unsigned field = 3; field < 22; ++field)
    {
        while (*cursor == ' ' || *cursor == '\t') ++cursor;
        if (!*cursor) return false;
        while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '\n') ++cursor;
    }
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    errno = 0;
    char* end = nullptr;
    unsigned long long startTicks = strtoull(cursor, &end, 10);
    if (end == cursor || errno != 0 || startTicks == 0) return false;
    session.processStartTicks = static_cast<uint64_t>(startTicks);

    char executable[sizeof(session.executablePath)];
    const ssize_t pathBytes = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (pathBytes <= 0 || static_cast<size_t>(pathBytes) >= sizeof(executable) - 1) return false;
    executable[pathBytes] = '\0';
    struct stat info{};
    if (stat("/proc/self/exe", &info) != 0 || !S_ISREG(info.st_mode) || info.st_size <= 0 ||
        info.st_ino == 0) return false;
    session.executableDevice = static_cast<uint64_t>(info.st_dev);
    session.executableInode = static_cast<uint64_t>(info.st_ino);
    session.executableBytes = static_cast<uint64_t>(info.st_size);
    memcpy(session.executablePath, executable, static_cast<size_t>(pathBytes) + 1);
    return true;
}

bool captureFrame(dcg01_raw::Direction direction, dcg01_raw::ReceiveMark mark,
    const unsigned char* frame, size_t frameBytes)
{
    const dcg01_raw::CaptureResult result = g_frameJournal.Capture(direction, mark, frame, frameBytes);
    if (result == dcg01_raw::CaptureResult::Captured) return true;
    fail(result == dcg01_raw::CaptureResult::Capacity ? Capacity : Envelope);
    return false;
}

bool configureFrameSession(const unsigned char peerCertificateSha256[SHA256_DIGEST_LENGTH],
    uint32_t tlsVersion, bool peerCertificateVerified, bool sessionReused)
{
    dcg01_raw::SessionContext session{};
    session.localMember = config.localId;
    session.peerMember = config.peerId;
    session.tlsVersion = tlsVersion;
    session.peerCertificateVerified = peerCertificateVerified ? 1 : 0;
    session.sessionReused = sessionReused ? 1 : 0;
    memcpy(session.runId, config.run, sizeof(session.runId));
    memcpy(session.manifestSha256, config.manifest, sizeof(session.manifestSha256));
    memcpy(session.localIncarnation, config.localInc, sizeof(session.localIncarnation));
    memcpy(session.peerIncarnation, config.peerInc, sizeof(session.peerIncarnation));
    memcpy(session.peerCertificateSha256, peerCertificateSha256, sizeof(session.peerCertificateSha256));
    if (!peerCertificateVerified || sessionReused || !captureProcessIdentity(session) ||
        !g_frameJournal.Configure(session)) return false;
    disconnectSession.localMember=config.localId;disconnectSession.peerMember=config.peerId;
    disconnectSession.tlsVersion=tlsVersion;disconnectSession.authenticated=true;
    disconnectSession.sessionReused=sessionReused;
    memcpy(disconnectSession.run,config.run,16);memcpy(disconnectSession.manifest,config.manifest,32);
    memcpy(disconnectSession.localIncarnation,config.localInc,16);memcpy(disconnectSession.peerIncarnation,config.peerInc,16);
    memcpy(disconnectSession.peerCertificate,peerCertificateSha256,32);
    memcpy(disconnectSession.expectedPeerCertificate,config.peerPin,32);
    return true;
}

void physicalDisconnect(bool writing, int result, int sslError, int socketError,
    unsigned long tlsError, uint64_t sent, uint64_t received, unsigned partialInputBytes)
{
    g_frameJournal.MarkIncomplete();
    uint64_t expected=0;
    if (!stats[1].compare_exchange_strong(expected,PeerDisconnected)) return;
    DCG01Disconnect::Notice notice=disconnectSession;
    notice.write=writing;notice.result=result;notice.sslError=sslError;notice.socketError=socketError;
    notice.tlsError=tlsError;notice.sent=sent;notice.received=received;notice.partialInputBytes=partialInputBytes;
    if (g_threadTerminal.PhysicalDisconnect(notice))
    {
        uint64_t ready=2;
        stats[0].compare_exchange_strong(ready,4); // Never overwrite a concurrent fatal state.
    }
    else
    {
        g_threadTerminal.Fail(DCG01Terminal::Origin::Transport,PeerDisconnected,nullptr);
        DistributedEvidenceTransportFailure(PeerDisconnected);
        stats[0].store(3);
    }
}

// Diagnostic export outcome is exposed through command-3 slots 18 (0=not configured,
// 1=complete, 2=incomplete, 3=rejected, 4=already exists, 5=failed) and 19 (errno).
// Existing wait counters in slots 16/17 are preserved. This never changes transport or
// terminal status.
dcg01_raw::custody::Result persistStoppedFrameJournal(const ConfigData& frozenConfig)
{
    using dcg01_raw::custody::Result;
    using dcg01_raw::custody::ResultCode;
    Result result = { ResultCode::Rejected, 0, ENODATA, 0 };
    dcg01_raw::FrameMeta* rows = static_cast<dcg01_raw::FrameMeta*>(
        malloc(sizeof(dcg01_raw::FrameMeta) * dcg01_raw::kRawFrameLimit));
    unsigned char* frameBytes = static_cast<unsigned char*>(malloc(dcg01_raw::kRawByteLimit));
    if (!rows || !frameBytes)
    {
        free(rows); free(frameBytes);
        result.code = ResultCode::Failed;
        result.errorNumber = ENOMEM;
        return result;
    }
    dcg01_raw::SessionContext session{};
    dcg01_raw::SnapshotInfo info{};
    if (!g_frameJournal.Snapshot(&session, rows, dcg01_raw::kRawFrameLimit,
        frameBytes, dcg01_raw::kRawByteLimit, &info) || !info.transportStopped)
    {
        free(rows); free(frameBytes);
        result.errorNumber = EBUSY;
        return result;
    }
    const int directoryFd = dcg01_raw::custody::OpenAdmittedManifestDirectory(
        frozenConfig.admissionManifest, session.manifestSha256);
    if (directoryFd < 0)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno != 0 ? errno : EIO;
        free(rows); free(frameBytes);
        return result;
    }
    char name[NAME_MAX + 1];
    if (!dcg01_raw::custody::FormatArtifactName(session, name, sizeof(name)))
    {
        close(directoryFd);
        result.code = ResultCode::Rejected;
        result.errorNumber = EINVAL;
        free(rows); free(frameBytes);
        return result;
    }
    result = dcg01_raw::custody::PersistStoppedSnapshot(directoryFd, name,
        &session, rows, frameBytes, &info);
    const int savedError = result.errorNumber;
    if (close(directoryFd) != 0 && result.code != ResultCode::AlreadyExists)
    {
        result.code = ResultCode::Failed;
        result.errorNumber = errno;
    }
    else if (result.errorNumber == 0) result.errorNumber = savedError;
    free(rows);
    free(frameBytes);
    return result;
}

uint64_t custodyResultStat(dcg01_raw::custody::ResultCode code)
{
    return static_cast<uint64_t>(code) + 1;
}

void recordCustodyResult(const dcg01_raw::custody::Result& result)
{
    stats[18].store(custodyResultStat(result.code), std::memory_order_release);
    stats[19].store(static_cast<uint64_t>(result.errorNumber), std::memory_order_release);
}

uint64_t get(const unsigned char* p, unsigned n)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < n; ++i) result = (result << 8) | p[i];
    return result;
}
void put(unsigned char* p, unsigned n, uint64_t value)
{
    for (unsigned i = n; i != 0; --i) { p[i - 1] = value & 255; value >>= 8; }
}
bool hex(const char* name, unsigned char* out, unsigned bytes)
{
    const char* s = getenv(name);
    if (!s || strlen(s) != bytes * 2) return false;
    for (unsigned i = 0; i < bytes; ++i)
    {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; ++j)
        {
            char c = s[2 * i + j];
            if (c >= '0' && c <= '9') value = value * 16 + c - '0';
            else if (c >= 'a' && c <= 'f') value = value * 16 + c - 'a' + 10;
            else return false;
        }
        out[i] = static_cast<unsigned char>(value);
    }
    return true;
}
bool number(const char* name, unsigned low, unsigned high, unsigned& value)
{
    const char* s = getenv(name);
    if (!s || !*s || strlen(s) > 5) return false;
    value = 0;
    for (; *s; ++s)
    {
        if (*s < '0' || *s > '9') return false;
        value = value * 10 + *s - '0';
    }
    return value >= low && value <= high;
}
bool path(const char* name, char* destination)
{
    const char* s = getenv(name);
    if (!s || s[0] != '/' || strlen(s) >= 512) return false;
    strcpy(destination, s);
    return true;
}
bool readConfig()
{
    const char* role = getenv("DC_CONTROL_ROLE");
    const char* address = getenv("DC_CONTROL_ADDRESS");
    unsigned port = 0;
    if (!role || (strcmp(role, "server") != 0 && strcmp(role, "client") != 0) || !address)
        return false;
    config.server = strcmp(role, "server") == 0;
    config.address.sin_family = AF_INET;
    if (inet_pton(AF_INET, address, &config.address.sin_addr) != 1 ||
        !number("DC_CONTROL_PORT", 1025, 65535, port) ||
        !number("DC_CONTROL_LOCAL_ID", 1, 2, config.localId) ||
        !number("DC_CONTROL_PEER_ID", 1, 2, config.peerId) || config.localId == config.peerId)
        return false;
    config.address.sin_port = htons(port);
    if (!path("DC_CONTROL_CA", config.ca) || !path("DC_CONTROL_CERT", config.cert) ||
        !path("DC_CONTROL_KEY", config.key) ||
        !hex("DC_CONTROL_RUN", config.run, 16) || !hex("DC_CONTROL_MANIFEST", config.manifest, 32) ||
        !hex("DC_CONTROL_LOCAL_INC", config.localInc, 16) || !hex("DC_CONTROL_PEER_INC", config.peerInc, 16) ||
        !hex("DC_CONTROL_PEER_SHA256", config.peerPin, 32))
        return false;
    if (DistributedAdmissionIsEnabled())
    {
        DistributedAdmissionJournalContext admitted{};
        if (!DistributedAdmissionCopyJournalContext(&admitted) ||
            config.localId != admitted.localNode || config.peerId != admitted.peerNode ||
            memcmp(config.run, admitted.run, sizeof(config.run)) != 0 ||
            memcmp(config.manifest, admitted.manifestSha256, sizeof(config.manifest)) != 0 ||
            memcmp(config.localInc, admitted.localIncarnation, sizeof(config.localInc)) != 0 ||
            memcmp(config.peerInc, admitted.peerIncarnation, sizeof(config.peerInc)) != 0)
            return false;
        memcpy(config.admissionManifest, admitted.manifestPath, sizeof(config.admissionManifest));
    }
    return true;
}
bool waitSocket(int fd, short events, uint64_t end)
{
    if (stop.load() || abortRequested.load()) return false;
    if (now() >= end) { fail(Deadline); return false; }
    pollfd p{fd, events, 0};
    int result = poll(&p, 1, 2);
    if (result < 0 && errno != EINTR) { fail(Socket); return false; }
    return true; // I/O calls, not readiness alone, decide EOF/error.
}
int connectSocket()
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { fail(Socket); return -1; }
    // Bound OS buffers as well as the application queues. Receive space exceeds
    // all permitted uncredited data, so write retries cannot trap healthy peers.
    int sendBytes = 4096, receiveBytes = 32768;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sendBytes, sizeof(sendBytes)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receiveBytes, sizeof(receiveBytes)) != 0)
    { close(fd); fail(Socket); return -1; }
    const uint64_t end = now() + 5000;
    if (config.server)
    {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, reinterpret_cast<sockaddr*>(&config.address), sizeof(config.address)) != 0 ||
            listen(fd, 1) != 0) { close(fd); fail(Socket); return -1; }
        stats[15].store(1);
        int peer = -1;
        while (!stop.load() && !abortRequested.load())
        {
            peer = accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (peer >= 0) break;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { fail(Socket); break; }
            if (!waitSocket(fd, POLLIN, end)) break;
        }
        close(fd);
        fd = peer;
    }
    else
    {
        if (connect(fd, reinterpret_cast<sockaddr*>(&config.address), sizeof(config.address)) != 0)
        {
            if (errno != EINPROGRESS) { close(fd); fail(Socket); return -1; }
            bool connected = false;
            while (waitSocket(fd, POLLOUT, end))
            {
                pollfd p{fd, POLLOUT, 0};
                if (poll(&p, 1, 0) <= 0) continue;
                int error = 0;
                socklen_t length = sizeof(error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0)
                    fail(Socket);
                else connected = true;
                break;
            }
            if (!connected) { close(fd); return -1; }
        }
    }
    if (fd >= 0)
    {
        int one = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0)
        { close(fd); fail(Socket); return -1; }
    }
    return fd;
}
void header(unsigned char* b, unsigned kind, unsigned length, uint64_t sequence, uint64_t correlation)
{
    memset(b, 0, Header);
    memcpy(b, "DCC1", 4);
    put(b + 4, 2, 1); put(b + 6, 2, kind); put(b + 8, 4, length);
    put(b + 12, 4, config.localId); put(b + 16, 4, config.peerId);
    put(b + 24, 8, sequence);
    memcpy(b + 32, config.run, 16); memcpy(b + 48, config.manifest, 32);
    memcpy(b + 80, config.localInc, 16); memcpy(b + 96, config.peerInc, 16);
    put(b + 112, 8, 1); put(b + 120, 8, correlation);
}
bool dataKind(unsigned kind) { return kind >= 16 && kind <= 23; }
bool validHeader(const unsigned char* b)
{
    unsigned kind = get(b + 6, 2), length = get(b + 8, 4);
    uint64_t sequence = get(b + 24, 8), correlation = get(b + 120, 8);
    bool shape = (kind >= 1 && kind <= 4 && length == 0 && sequence == 0 && correlation != 0) ||
        (dataKind(kind) && length > 0 && length <= Payload &&
         sequence != 0 && correlation == sequence);
    return shape && memcmp(b, "DCC1", 4) == 0 && get(b + 4, 2) == 1 &&
        get(b + 12, 4) == config.peerId && get(b + 16, 4) == config.localId &&
        get(b + 20, 4) == 0 && get(b + 112, 8) == 1 &&
        memcmp(b + 32, config.run, 16) == 0 && memcmp(b + 48, config.manifest, 32) == 0 &&
        memcmp(b + 80, config.peerInc, 16) == 0 && memcmp(b + 96, config.localInc, 16) == 0;
}

void exchange(SSL* ssl, int fd)
{
    // Every SSL call and this bounded state belong solely to this native thread.
    unsigned char input[FrameSize]{}, output[FrameSize]{}, digests[DataSlots][SHA256_DIGEST_LENGTH]{};
    unsigned inputSize = 0, inputTarget = Header, outputSize = 0, outputOffset = 0;
    uint64_t inputStart = 0, inputWindow = 0, outputStart = 0, outputWindow = 0;
    bool outputAttempted = false;
    uint64_t received = 0, sent = 0, credited = 0, creditSent = 0;
    uint64_t nextPing = 0, pendingPing = 0, pingStarted = 0, lastPong = 0, peerPing = 0, lastPingTime = 0;
    Control controls[ControlSlots]{};
    unsigned controlHead = 0, controlCount = 0;
    auto enqueueControl = [&](unsigned kind, uint64_t correlation, uint64_t window) {
        if (controlCount == ControlSlots) { fail(Capacity); return false; }
        controls[(controlHead + controlCount) % ControlSlots] = {kind, correlation, window};
        ++controlCount;
        return true;
    };
    int readWant = SSL_ERROR_WANT_READ, writeWant = SSL_ERROR_WANT_WRITE;
    // Keep a locally requested abort drainable when Stop immediately follows Abort.
    // The existing per-write deadline still bounds an unavailable peer; no success is inferred.
    while (!stop.load() || abortRequested.load())
    {
        if (!abortRequested.load() &&
            ((inputStart && now() - inputStart >= 2000) ||
             (pendingPing && now() - pingStarted >= 5000)))
        { fail(Deadline); break; }
        if (abortRequested.load())
        {
            // Abort is latched locally immediately. A pending TLS write must be retried
            // with identical arguments before any abort frame can replace it.
            if (outputSize == 0)
            {
                header(output, 3, 0, 0, LocalAbort);
                outputSize = Header; outputOffset = 0; outputStart = now(); outputWindow = 0;
                outputAttempted = false;
            }
        }
        else if (stats[1].load() != 0) break;

        // A WANT_WRITE result forbids intervening SSL I/O until this exact
        // write is retried. WANT_READ permits reading before the write retry.
        if (!abortRequested.load() && !(outputSize && writeWant == SSL_ERROR_WANT_WRITE))
        {
            size_t count = 0;
            uint64_t readWindow = gcWindow.load();
            ERR_clear_error();
            errno = 0;
            int result = SSL_read_ex(ssl, input + inputSize, inputTarget - inputSize, &count);
            if (result == 1)
            {
                readWant = SSL_ERROR_WANT_READ;
                if (inputSize == 0) { inputStart = now(); inputWindow = readWindow; }
                // Every successful fragment read must begin and finish in the
                // same still-open real EE suspension window as the PONG write.
                if (readWindow != inputWindow || gcWindow.load() != inputWindow)
                    inputWindow = 0;
                inputSize += static_cast<unsigned>(count);
                if (inputSize == Header && inputTarget == Header)
                {
                    if (!validHeader(input)) { fail(Envelope); break; }
                    inputTarget = Header + get(input + 8, 4);
                }
                if (inputSize == inputTarget)
                {
                    unsigned kind = get(input + 6, 2);
                    uint64_t sequence = get(input + 24, 8), correlation = get(input + 120, 8);
                    if (kind >= 16)
                    {
                        unsigned char digest[SHA256_DIGEST_LENGTH];
                        if (!SHA256(input, inputTarget, digest)) { fail(Tls); break; }
                        if (sequence <= received)
                        {
                            if (received - sequence >= DataSlots ||
                                CRYPTO_memcmp(digests[sequence % DataSlots], digest, sizeof(digest)) != 0)
                            { fail(Sequence); break; }
                            stats[4].fetch_add(1);
                             if (!captureFrame(dcg01_raw::Inbound, dcg01_raw::ReceiveMark::DuplicateAccepted, input, inputTarget)) break;
                        }
                        else
                        {
                            if (received == UINT64_MAX || sequence != received + 1) { fail(Sequence); break; }
                            pthread_mutex_lock(&queueLock);
                            bool full = rxCount == DataSlots;
                            if (!full)
                            {
                                Item& item = rx[(rxHead + rxCount) % DataSlots];
                                item.kind = kind; item.sequence = sequence;
                                item.length = inputTarget - Header;
                                memcpy(item.body, input + Header, item.length);
                                ++rxCount;
                                stats[9].store(rxCount);
                            }
                            pthread_mutex_unlock(&queueLock);
                            if (full) { fail(Capacity); break; }
                            memcpy(digests[sequence % DataSlots], digest, sizeof(digest));
                            received = sequence; stats[3].fetch_add(1);
                             if (!captureFrame(dcg01_raw::Inbound, dcg01_raw::ReceiveMark::NewFrame, input, inputTarget)) break;
                        }
                    }
                    else
                    {
                        stats[14].fetch_add(1);
                        bool duplicateControl = false;
                        bool acceptedControl = false;
                        if (kind == 1)
                        {
                            if (correlation < peerPing) { fail(Sequence); break; }
                            duplicateControl = correlation == peerPing;
                            peerPing = correlation;
                            stats[5].fetch_add(1);
                            if (!enqueueControl(2, correlation, inputWindow)) break;
                            acceptedControl = true;
                        }
                        else if (kind == 2)
                        {
                            if (correlation == pendingPing && pendingPing != 0)
                            { lastPong = correlation; pendingPing = 0; stats[6].fetch_add(1); acceptedControl = true; }
                            else if (correlation == lastPong && lastPong != 0)
                            { duplicateControl = true; acceptedControl = true; }
                            else { fail(Sequence); break; }
                        }
                        else if (kind == 3)
                        {
                            if (!captureFrame(dcg01_raw::Inbound, dcg01_raw::ReceiveMark::NewFrame, input, inputTarget)) break;
                            fail(PeerAbort); break;
                        }
                        else
                        {
                            if (correlation > sent) { fail(Sequence); break; }
                            duplicateControl = correlation <= credited;
                            if (correlation > credited) credited = correlation;
                            acceptedControl = true;
                        }
                        if (acceptedControl && !captureFrame(dcg01_raw::Inbound,
                            duplicateControl ? dcg01_raw::ReceiveMark::DuplicateAccepted : dcg01_raw::ReceiveMark::NewFrame,
                            input, inputTarget)) break;
                    }
                    inputSize = 0; inputTarget = Header; inputStart = 0; inputWindow = 0;
                }
            }
            else
            {
                const int socketError = errno;
                readWant = SSL_get_error(ssl, result);
                const unsigned long tlsError = ERR_peek_last_error();
                if (readWant != SSL_ERROR_WANT_READ && readWant != SSL_ERROR_WANT_WRITE)
                {
                    if (readWant == SSL_ERROR_ZERO_RETURN ||
                        (readWant == SSL_ERROR_SYSCALL && (result == 0 || socketError == ECONNRESET ||
                         socketError == ECONNABORTED || socketError == ENOTCONN)) ||
                        (readWant == SSL_ERROR_SSL && unexpectedTlsEof(tlsError)))
                        physicalDisconnect(false,result,readWant,socketError,tlsError,sent,received,inputSize);
                    else
                        fail(Tls);
                    break;
                }
            }
            if (abortRequested.load()) continue;
            if (stats[1].load() != 0 && !abortRequested.load()) break;

            if (outputSize == 0)
            {
                pthread_mutex_lock(&queueLock);
                uint64_t availableCredit = consumed;
                pthread_mutex_unlock(&queueLock);
                if (availableCredit > creditSent)
                { if (!enqueueControl(4, availableCredit, 0)) break; creditSent = availableCredit; }
                if (!pendingPing && now() - lastPingTime >= 10)
                {
                    if (nextPing == UINT64_MAX) { fail(Sequence); break; }
                    pendingPing = ++nextPing; pingStarted = lastPingTime = now();
                    if (!enqueueControl(1, pendingPing, 0)) break;
                }
                if (abortRequested.load()) continue;
                if (stats[1].load() != 0 && !abortRequested.load()) break;
                if (controlCount != 0)
                {
                    Control c = controls[controlHead];
                    controlHead = (controlHead + 1) % ControlSlots; --controlCount;
                    header(output, c.kind, 0, 0, c.correlation);
                    outputSize = Header; outputWindow = c.window;
                }
                else if (sent - credited < DataSlots)
                {
                    pthread_mutex_lock(&queueLock);
                    if (txCount != 0 && sent != UINT64_MAX)
                    {
                        Item& item = tx[txHead];
                        header(output, item.kind, item.length, sent + 1, sent + 1);
                        memcpy(output + Header, item.body, item.length);
                        outputSize = Header + item.length; outputWindow = 0;
                        txHead = (txHead + 1) % DataSlots; --txCount;
                        stats[10].store(txCount);
                    }
                    bool exhausted = txCount != 0 && sent == UINT64_MAX;
                    pthread_mutex_unlock(&queueLock);
                    if (exhausted) { fail(Sequence); break; }
                }
                if (outputSize) { outputStart = now(); outputOffset = 0; outputAttempted = false; }
            }
        }

        if (outputSize)
        {
            // Prefer abort over a merely prepared frame. Once an SSL write is
            // attempted its outcome may be uncertain; preserve its retry arguments.
            // A concurrent abort after this observation cannot retract admitted I/O.
            if (abortRequested.load() && !outputAttempted)
            {
                header(output, 3, 0, 0, LocalAbort);
                outputSize = Header; outputOffset = 0; outputStart = now(); outputWindow = 0;
            }
            outputAttempted = true;
            size_t count = 0;
            ERR_clear_error();
            errno = 0;
            int result = SSL_write_ex(ssl, output + outputOffset, outputSize - outputOffset, &count);
            if (result == 1)
            {
                outputOffset += static_cast<unsigned>(count);
                if (outputOffset == outputSize)
                {
                    unsigned kind = get(output + 6, 2);
                    if (kind >= 16) { ++sent; stats[2].fetch_add(1); }
                    if (!captureFrame(dcg01_raw::Outbound, dcg01_raw::ReceiveMark::NewFrame, output, outputSize)) break;
                    if (kind == 2 && outputWindow != 0 && gcWindow.load() == outputWindow)
                        stats[7].fetch_add(1);
                    outputSize = 0;
                    if (kind == 3) break;
                }
            }
            else
            {
                const int socketError = errno;
                writeWant = SSL_get_error(ssl, result);
                const unsigned long tlsError = ERR_peek_last_error();
                if (writeWant == SSL_ERROR_WANT_WRITE) stats[16].fetch_add(1);
                if (writeWant == SSL_ERROR_WANT_READ) stats[17].fetch_add(1);
                if (writeWant != SSL_ERROR_WANT_READ && writeWant != SSL_ERROR_WANT_WRITE)
                {
                    if (writeWant == SSL_ERROR_ZERO_RETURN ||
                        (writeWant == SSL_ERROR_SYSCALL && (socketError == EPIPE || socketError == ECONNRESET ||
                         socketError == ECONNABORTED || socketError == ENOTCONN)) ||
                        (writeWant == SSL_ERROR_SSL && unexpectedTlsEof(tlsError)))
                        physicalDisconnect(true,result,writeWant,socketError,tlsError,sent,received,inputSize);
                    else
                        fail(Tls);
                    break;
                }
            }
            if (outputSize && now() - outputStart >= 2000) { fail(Deadline); break; }
        }
        // Buffered/readable input cannot unblock a WANT_WRITE retry. Wait only
        // for the outstanding operation's required direction in that state.
        bool wantsWrite = outputSize ? writeWant == SSL_ERROR_WANT_WRITE : readWant == SSL_ERROR_WANT_WRITE;
        pollfd p{fd, static_cast<short>(wantsWrite ? POLLOUT : POLLIN), 0};
        if ((wantsWrite || SSL_pending(ssl) == 0) && poll(&p, 1, 2) < 0 && errno != EINTR)
        { fail(Socket); break; }
    }
}
void* run(void*)
{
    stats[12].store(1);
    // OpenSSL writes must not deliver SIGPIPE to the runtime or change its global disposition.
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &mask, nullptr) != 0) { fail(Thread); stats[12].store(0); return nullptr; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    SSL* ssl = nullptr;
    int fd = -1;
    bool ready = ctx && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_max_early_data(ctx, 0) == 1 && SSL_CTX_set_num_tickets(ctx, 0) == 1;
    if (ready)
    {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_verify_depth(ctx, 3);
        SSL_CTX_set_max_cert_list(ctx, 16 * 1024);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        ready = SSL_CTX_load_verify_locations(ctx, config.ca, nullptr) == 1 &&
            SSL_CTX_use_certificate_chain_file(ctx, config.cert) == 1 &&
            SSL_CTX_use_PrivateKey_file(ctx, config.key, SSL_FILETYPE_PEM) == 1 &&
            SSL_CTX_check_private_key(ctx) == 1;
    }
    if (!ready) fail(Config);
    else
    {
        fd = connectSocket();
        if (fd >= 0)
        {
            ssl = SSL_new(ctx);
            if (!ssl || SSL_set_fd(ssl, fd) != 1) fail(Tls);
            else
            {
                if (config.server) SSL_set_accept_state(ssl); else SSL_set_connect_state(ssl);
                uint64_t end = now() + 5000;
                while (!stop.load() && !abortRequested.load())
                {
                    ERR_clear_error();
                    int result = SSL_do_handshake(ssl);
                    if (result == 1)
                    {
                        X509* peer = SSL_get1_peer_certificate(ssl);
                        unsigned char pin[SHA256_DIGEST_LENGTH]; unsigned size = 0;
                        bool authenticated = peer && SSL_get_verify_result(ssl) == X509_V_OK &&
                            X509_digest(peer, EVP_sha256(), pin, &size) == 1 && size == sizeof(pin) &&
                            CRYPTO_memcmp(pin, config.peerPin, sizeof(pin)) == 0 && !SSL_session_reused(ssl);
                        X509_free(peer);
                        if (!authenticated) fail(Identity);
                         else if (!configureFrameSession(pin, static_cast<uint32_t>(SSL_version(ssl)),
                             authenticated, SSL_session_reused(ssl) != 0)) fail(Identity);
                        else
                        {
                            stats[13].store(SSL_version(ssl));
                            uint64_t expected = 1;
                            if (stats[0].compare_exchange_strong(expected, 2)) exchange(ssl, fd);
                        }
                        break;
                    }
                    int error = SSL_get_error(ssl, result);
                    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) { fail(Tls); break; }
                    if (!waitSocket(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, end)) break;
                }
            }
        }
    }
    // A coordinator that has published its terminal record closes the retired
    // worker with TLS close_notify. This is resource teardown, not a success vote.
    // Fatal/uncertain sessions do not send a clean close alert.
    if (ssl && fd >= 0 && stop.load() && stats[1].load() == 0)
    {
        const uint64_t closeDeadline = now() + 1000;
        while (now() < closeDeadline)
        {
            ERR_clear_error();
            errno = 0;
            const int result = SSL_shutdown(ssl);
            if (result >= 0) break; // 0 means our close_notify was sent.
            const int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) break;
            pollfd closePoll{fd, static_cast<short>(error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0};
            const uint64_t current = now();
            if (current >= closeDeadline) break;
            const int remaining = static_cast<int>(closeDeadline - current);
            if (poll(&closePoll, 1, remaining) <= 0) break;
        }
    }
    // No completion is inferred from TLS close. Fatal/uncertain sessions do not replay.
    SSL_free(ssl);
    if (fd >= 0) close(fd);
    SSL_CTX_free(ctx);
    if (stats[0].load() != 3) stats[0].store(4);
    stats[12].store(0);
    return nullptr;
}
} // namespace

static bool HashThreadFailure(const unsigned char* bytes, size_t length, unsigned char* digest)
{
    return (bytes != nullptr || length == 0) && digest != nullptr && SHA256(bytes,length,digest) != nullptr;
}

extern "C" bool DistributedThreadTerminalConfigure(const DistributedAdmissionThreadIdentity* identity)
{
    return g_threadTerminal.Configure(identity, HashThreadFailure);
}
extern "C" void DistributedThreadTerminalFailure(unsigned origin, unsigned code, const char* reason)
{
    // Unknown origins still fail closed; callers cannot turn malformed evidence into health.
    g_threadTerminal.Fail(static_cast<DCG01Terminal::Origin>(origin), code, reason);
}
extern "C" bool DistributedThreadTerminalHealthy()
{
    return g_threadTerminal.Healthy();
}
extern "C" bool DistributedThreadTerminalPeerDisconnected()
{
    return g_threadTerminal.PeerDisconnected();
}
extern "C" bool DistributedThreadTerminalPrepareDrain()
{
    return g_threadTerminal.PrepareTransportDrain();
}
extern "C" bool DistributedThreadTerminalDraining()
{
    return g_threadTerminal.DrainingRetiredService();
}
extern "C" bool DistributedThreadTerminalCopyFailure(DCG01Terminal::FailureSnapshot* output)
{
    return g_threadTerminal.Copy(output);
}
extern "C" bool DistributedThreadTerminalLifecycle(unsigned kind, uint64_t frontier)
{
    return g_threadTerminal.RecordLifecycle(static_cast<DCG01Events::Lifecycle>(kind), frontier);
}
extern "C" bool DistributedThreadTerminalCopyTrace(unsigned char* output, size_t capacity, size_t* length, uint64_t* count)
{
    return g_threadTerminal.CopyTrace(output, capacity, length, count);
}
extern "C" bool DistributedThreadTerminalAccess(unsigned actor, const unsigned char* request, const unsigned char* reply, size_t length, uint64_t before)
{
    DCG01Events::AccessDiagnostic diagnostic{};
    const bool accepted = g_threadTerminal.AccessEvent(actor, request, reply, length, before, &diagnostic);
    if (!accepted)
        fprintf(stderr, "DC_ACCESS_DIAG phase=%s check=%s node=%u actor=%u events=%llu/%llu bytes=%zu/%zu\n",
            diagnostic.phase, diagnostic.check, diagnostic.node, diagnostic.actor,
            static_cast<unsigned long long>(diagnostic.events),
            static_cast<unsigned long long>(diagnostic.eventLimit), diagnostic.used, diagnostic.byteLimit);
    return accepted;
}

extern "C" bool DistributedThreadTerminalPublication(unsigned kind, uint64_t id, const unsigned char* root, const unsigned char* objects, unsigned count)
{
    return g_threadTerminal.PublicationEvent(static_cast<DCG01Events::Publication>(kind), id, root, objects, count);
}

extern "C" bool DistributedThreadTerminalAdmissionClosed(unsigned actor, uint64_t generation, uint64_t sequence)
{
    return g_threadTerminal.AdmissionClosed(actor, generation, sequence);
}

extern "C" bool DistributedThreadTerminalRoots(unsigned kind, const unsigned char* objects, unsigned count)
{
    return g_threadTerminal.RootEvent(kind, objects, count);
}

extern "C" bool DistributedThreadTerminalArtifact(unsigned id, unsigned role, const unsigned char* bytes, size_t length)
{
    unsigned char digest[32]{};
    const bool valid = bytes != nullptr && length <= 16384 && SHA256(bytes,length,digest) != nullptr;
    return g_threadTerminal.ArtifactEvent(id,role,valid ? bytes : nullptr,length,digest);
}

extern "C" bool DistributedThreadTerminalCommitWorker(uint64_t operations, uint64_t authority, uint64_t publications,
    const DCG01Custody::Bundle* sent, const unsigned char* ack, size_t ackLength, DCG01Commit::Frame* output)
{
    return g_threadTerminal.CommitWorker(operations,authority,publications,sent,ack,ackLength,output);
}

extern "C" bool DistributedThreadTerminalReceiveWorkerCommit(const DCG01Custody::Bundle* custody,
    const unsigned char* wire, size_t length)
{
    return g_threadTerminal.ReceiveWorkerCommit(custody,wire,length);
}

extern "C" bool DistributedThreadTerminalCommitLocal()
{
    return g_threadTerminal.CommitLocal();
}

extern "C" bool DistributedThreadTerminalRetireWorker()
{
    return g_threadTerminal.RetireWorker();
}

extern "C" bool DistributedThreadTerminalPrepared(unsigned member, const unsigned char* body, size_t length)
{
    return g_threadTerminal.PrepareEvent(member,body,length);
}

extern "C" bool DistributedThreadTerminalMainReturned(int32_t result, uint64_t operation, uint64_t authority, uint64_t publication)
{
    return g_threadTerminal.MainReturned(result,operation,authority,publication);
}

static DistributedAdmissionJournalContext ThreadEvidenceContext()
{
    DistributedAdmissionJournalContext context{};
    pthread_mutex_lock(&lifecycleLock);
    memcpy(context.run,config.run,16);memcpy(context.manifestSha256,config.manifest,32);
    context.localNode=config.localId;context.peerNode=config.peerId;
    memcpy(context.localIncarnation,config.localInc,16);memcpy(context.peerIncarnation,config.peerInc,16);
    memcpy(context.manifestPath,config.admissionManifest,sizeof(context.manifestPath));
    pthread_mutex_unlock(&lifecycleLock);return context;
}
extern "C" DCG01Terminal::PublicationResult DistributedThreadTerminalPublishRecord()
{
    using Result=DCG01Terminal::PublicationResult;
    const uint64_t custody=stats[18].load();
    if(!g_threadTerminal.DrainingRetiredService() || stats[0].load()!=4 || stats[12].load()!=0 || stats[9].load()!=0 ||
        (custody!=1 && !(custody==2 && g_threadTerminal.PeerDisconnected())))
    {
        g_threadTerminal.Fail(DCG01Terminal::Origin::Evidence,17,"terminal-producer-or-journal-custody");return Result::Failed;
    }
    const auto context=ThreadEvidenceContext();
    const auto result=DCG01TerminalFiles::Publish(g_threadTerminal,context);
    const bool okay=result!=Result::Failed;
    fprintf(stderr,"DC_THREAD phase=terminal-publication node=1 status=%s terminal=%u\n",okay?"complete":"incomplete",okay?1u:0u);
    if(result==Result::ExportIncomplete)
        fprintf(stderr,"DC_THREAD phase=terminal-file-export status=incomplete record=published terminal=0\n");
    return result;
}
extern "C" bool DistributedThreadTerminalPersistFailure()
{
    const auto context=ThreadEvidenceContext();
    const bool okay=DCG01TerminalFiles::PersistFailure(g_threadTerminal,context);
    if(!okay) fprintf(stderr,"DC_THREAD phase=terminal-failure-export status=failed errno=%d\n",errno);
    return okay;
}

extern "C" int64_t DistributedControlNative(int command, int argument, unsigned char* buffer, int length)
{
    if (length < 0 || (length > 0 && !buffer)) return -1;
    if (command == 0)
    {
        if (argument != 0 || length != 0) return -1;
        pthread_mutex_lock(&lifecycleLock);
        uint64_t expected = 0;
        int64_t result = -1;
        if (stats[0].compare_exchange_strong(expected, 1))
        {
            if (!readConfig()) fail(Config);
            else if (pthread_create(&worker, nullptr, run, nullptr) != 0) fail(Thread);
            else { created = true; result = 0; }
        }
        pthread_mutex_unlock(&lifecycleLock);
        return result;
    }
    if (command == 3)
        return argument >= 0 && argument < 20 && length == 0 ? static_cast<int64_t>(stats[argument].load()) : -1;
    if (command == 4)
    {
        if (argument != 0 || length != 0) return -1;
        pthread_mutex_lock(&lifecycleLock);
        // Order shutdown publication against producer admission. Do not hold
        // queueLock while joining the worker.
        pthread_mutex_lock(&queueLock);
        stop.store(true);
        pthread_mutex_unlock(&queueLock);
        if (created)
        {
            int result = pthread_join(worker, nullptr);
            if (result != 0) { pthread_mutex_unlock(&lifecycleLock); return -1; }
            created = false;
        }
        g_frameJournal.MarkTransportStopped();
        if (stats[0].load() == 0) stats[0].store(4);
        // Freeze this one-shot run's admitted path while lifecycleLock still
        // excludes command-0 configuration. No reset/reconfigure path exists.
        const ConfigData stoppedConfig = config;
        const bool persistJournal=!journalPersistenceClaimed;
        journalPersistenceClaimed=true;
        pthread_mutex_unlock(&lifecycleLock);

        if (!persistJournal) return 0; // Later host cleanup preserves the first custody result.

        // The producer is joined and the journal marked stopped. Snapshot and
        // durable I/O run after releasing lifecycleLock. This local diagnostic
        // is deliberately not a terminal, coordinator, or success decision.
        if (stoppedConfig.admissionManifest[0] != 0)
        {
            const dcg01_raw::custody::Result custody = persistStoppedFrameJournal(stoppedConfig);
            recordCustodyResult(custody);
        }
        else if (DistributedAdmissionIsEnabled())
        {
            const dcg01_raw::custody::Result custody = {
                dcg01_raw::custody::ResultCode::Rejected, 0, EPERM, 0 };
            recordCustodyResult(custody); // Admission failed before a trusted manifest path was copied.
        }
        return 0;
    }
    if (command == 5)
    {
        if (argument != 0 || length != 0) return -1;
        // Serialize abort publication against producer admission. The callback
        // is deliberately outside queueLock because it takes evidence locks.
        pthread_mutex_lock(&queueLock);
        if (stats[0].load() != 2)
        {
            pthread_mutex_unlock(&queueLock);
            return -1;
        }
        abortRequested.store(true);
        pthread_mutex_unlock(&queueLock);
        fail(LocalAbort);
        return 0;
    }
    if (command == 1)
    {
        if (!dataKind(static_cast<unsigned>(argument)) ||
            length < 1 || length > static_cast<int>(Payload)) return -1;
        pthread_mutex_lock(&queueLock);
        int result = -1;
        if (stats[0].load() == 2 && !abortRequested.load() && !stop.load())
        {
            result = 1;
            if (txCount < DataSlots)
            {
                Item& item = tx[(txHead + txCount) % DataSlots];
                item.kind = argument; item.length = length;
                memcpy(item.body, buffer, length);
                ++txCount; stats[10].store(txCount); result = 0;
            }
            else stats[8].fetch_add(1);
        }
        pthread_mutex_unlock(&queueLock);
        return result;
    }
    if (command == 2)
    {
        // Already received, authenticated records remain drainable after a
        // transport failure. The caller must still process/latch the failure;
        // draining cannot revive a rejected terminal cut.
        if (argument != 0 || length < static_cast<int>(Payload + 16)) return -1;
        pthread_mutex_lock(&queueLock);
        int result = 0;
        if (rxCount)
        {
            Item& item = rx[rxHead];
            put(buffer, 8, item.sequence); put(buffer + 8, 8, item.kind);
            memcpy(buffer + 16, item.body, item.length);
            result = item.length; consumed = item.sequence;
            rxHead = (rxHead + 1) % DataSlots; --rxCount; stats[9].store(rxCount);
        }
        pthread_mutex_unlock(&queueLock);
        return result;
    }
    return -1;
}
extern "C" void DistributedControlAfterSuspend()
{
    if (stats[0].load() == 2)
    {
        uint64_t epoch = gcNext.fetch_add(1) + 1;
        gcWindow.store(epoch);
        stats[11].fetch_add(1);
    }
}
extern "C" void DistributedControlBeforeResume() { gcWindow.store(0); }

extern "C" bool DistributedControlFrameJournalSnapshot(dcg01_raw::SessionContext* session,
    dcg01_raw::FrameMeta* rows, size_t rowCapacity, unsigned char* frameBytes,
    size_t byteCapacity, dcg01_raw::SnapshotInfo* info)
{
    return g_frameJournal.Snapshot(session, rows, rowCapacity, frameBytes, byteCapacity, info);
}

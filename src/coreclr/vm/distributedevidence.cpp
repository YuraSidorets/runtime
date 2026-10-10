#include "distributedevidence.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace
{
constexpr size_t kHeaderBytes = 128;
constexpr size_t kEventHeaderBytes = 160;
constexpr size_t kEventPayloadLimit = 256;
constexpr size_t kEventBytesLimit = kEventHeaderBytes + kEventPayloadLimit;
constexpr size_t kEventsPerNodeLimit = 32;
constexpr size_t kFooterBytes = 64;
constexpr size_t kArtifactBytesLimit = kHeaderBytes + 2 * kEventsPerNodeLimit * kEventBytesLimit + kFooterBytes;
constexpr size_t kWorkerBytesLimit = kEventsPerNodeLimit * kEventBytesLimit;

enum class State { Empty, Active, WorkerFrozen, WorkerRetired, CoordinatorSealed, Publishing, PublishingAbort, Failed, Written };
std::mutex g_lock;
State g_state = State::Empty;
bool g_aborted = false;
bool g_coordinator = false;
bool g_emptyProbe = false;
uint32_t g_coordNode = 0, g_workerNode = 0, g_localNode = 0;
unsigned char g_run[16]{}, g_manifest[32]{}, g_topology[32]{};
unsigned char g_coordInc[16]{}, g_workerInc[16]{}, g_localInc[16]{};
std::string g_recordPath;
std::vector<std::vector<unsigned char>> g_localRecords;
std::vector<std::vector<unsigned char>> g_workerRecords;
std::vector<std::vector<unsigned char>> g_allRecords;
uint64_t g_lastMonotonic[2]{};
unsigned char g_workerDigest[32]{};
uint32_t g_workerPayloadBytes = 0;
bool g_custodyReady = false;
bool g_transportDisconnected = false;
bool g_hasResult = false;
int32_t g_resultCode = 0;
unsigned char g_resultDigest[32]{};
unsigned char g_custodyReceipt[160]{};
bool g_custodyReceiptValid = false;
unsigned char g_terminalPrepare[152]{};
bool g_terminalPrepareValid = false;

void Put16(unsigned char* p, uint16_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
void Put32(unsigned char* p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = (unsigned char)(v >> (i * 8)); }
void Put64(unsigned char* p, uint64_t v) { for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (i * 8)); }
uint16_t Get16(const unsigned char* p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
uint32_t Get32(const unsigned char* p) { uint32_t v = 0; for (unsigned i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (i * 8); return v; }
uint64_t Get64(const unsigned char* p) { uint64_t v = 0; for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8); return v; }

bool Hash(const unsigned char* bytes, size_t count, unsigned char output[32])
{
    unsigned length = 0;
    return bytes != nullptr && EVP_Digest(bytes, count, output, &length, EVP_sha256(), nullptr) == 1 && length == 32;
}

bool AllZero(const unsigned char* p, size_t n)
{
    unsigned char v = 0;
    for (size_t i = 0; i < n; ++i) v |= p[i];
    return v == 0;
}

bool Times(uint64_t& monotonic, uint64_t& wall)
{
    timespec m{}, r{};
    if (clock_gettime(CLOCK_MONOTONIC, &m) != 0 || clock_gettime(CLOCK_REALTIME, &r) != 0 ||
        m.tv_sec < 0 || r.tv_sec < 0) return false;
    monotonic = (uint64_t)m.tv_sec * 1000000000ULL + (uint64_t)m.tv_nsec;
    wall = (uint64_t)r.tv_sec * 1000000000ULL + (uint64_t)r.tv_nsec;
    const unsigned slot = g_localNode == g_coordNode ? 0 : 1;
    if (monotonic < g_lastMonotonic[slot]) return false;
    g_lastMonotonic[slot] = monotonic;
    return true;
}

bool SameIdentity(const unsigned char* p, uint32_t node, const unsigned char incarnation[16])
{
    return Get32(p) == node && std::memcmp(p + 4, incarnation, 16) == 0;
}

bool ExpectedLocalKind(size_t sequence, uint16_t kind)
{
    static const uint16_t coordinator[] = {
        DE_ADMISSION_PREPARED, DE_ENTRY_MATCHED, DE_PEER_READY_RECEIVED, DE_GRANT_SENT,
        DE_COORDINATOR_STAGED_ACK_RECEIVED, DE_MAIN_AUTHORIZATION_CONSUMED, DE_MAIN_STARTED,
        DE_MAIN_RETURNED, DE_COORDINATOR_TERMINAL_COMMIT, DE_TERMINAL_PREPARE_SENT,
        DE_CUSTODY_RECEIPT_SENT, DE_TERMINAL_ACK_RECEIVED, DE_WORKER_RETIRED,
        DE_CUT_SEALED, DE_RECORD_CANDIDATE_CLOSED
    };
    static const uint16_t worker[] = {
        DE_ADMISSION_PREPARED, DE_ENTRY_MATCHED, DE_WORKER_STAGED_ACK_SENT,
        DE_WORKER_STAGED, DE_WORKER_TERMINAL_COMMIT_PREPARED
    };
    if (g_coordinator)
    {
        if (kind == DE_POST_RETIREMENT_DISCONNECT && sequence == 14) return true;
        if (kind == DE_RECORD_CANDIDATE_CLOSED && sequence == 15 && !g_localRecords.empty() &&
            Get16(g_localRecords.back().data() + 6) == DE_POST_RETIREMENT_DISCONNECT) return true;
        return sequence < sizeof(coordinator) / sizeof(coordinator[0]) && coordinator[sequence] == kind;
    }
    return sequence < sizeof(worker) / sizeof(worker[0]) && worker[sequence] == kind;
}

bool ValidateDccr(const unsigned char* p)
{
    if (!p || std::memcmp(p, "DCCR", 4) != 0 || Get16(p + 4) != 1 || Get16(p + 6) != 160 ||
        std::memcmp(p + 8, g_run, 16) != 0 || std::memcmp(p + 24, g_manifest, 32) != 0 ||
        Get64(p + 56) != 1 || !SameIdentity(p + 64, g_coordNode, g_coordInc) ||
        !SameIdentity(p + 84, g_workerNode, g_workerInc) || Get64(p + 104) != 5 ||
        Get32(p + 112) != 5 || Get32(p + 116) != g_workerPayloadBytes ||
        std::memcmp(p + 120, g_workerDigest, 32) != 0 || !AllZero(p + 152, 8)) return false;
    return true;
}

bool ValidateDctp(const unsigned char* p)
{
    if (!p) return false;
    const uint32_t sender = g_coordNode;
    const unsigned char* senderInc = g_coordInc;
    const int32_t resultCode = (int32_t)Get32(p + 112);
    unsigned char resultBytes[4], resultHash[32];
    Put32(resultBytes, (uint32_t)resultCode);
    if (std::memcmp(p, "DCTP", 4) != 0 || Get16(p + 4) != 1 || Get16(p + 6) != 152 ||
        std::memcmp(p + 8, g_run, 16) != 0 || std::memcmp(p + 24, g_manifest, 32) != 0 ||
        Get64(p + 56) != 1 || !SameIdentity(p + 64, sender, senderInc) ||
        !SameIdentity(p + 84, g_workerNode, g_workerInc) || Get64(p + 104) != 9 ||
        !Hash(resultBytes, sizeof(resultBytes), resultHash) || std::memcmp(p + 116, resultHash, 32) != 0 ||
        Get32(p + 148) != 0) return false;
    if (g_coordinator)
    {
        if (!g_hasResult || resultCode != g_resultCode || std::memcmp(resultHash, g_resultDigest, 32) != 0)
            return false;
    }
    else
    {
        if (resultCode != 0) return false;
        g_resultCode = resultCode;
        std::memcpy(g_resultDigest, resultHash, 32);
        g_hasResult = true;
    }
    return true;
}

bool ValidateDcta(const unsigned char* p)
{
    unsigned char receiptHash[32];
    if (!g_custodyReceiptValid || !p || !Hash(g_custodyReceipt, sizeof(g_custodyReceipt), receiptHash) ||
        std::memcmp(p, "DCTA", 4) != 0 || Get16(p + 4) != 1 || Get16(p + 6) != 176 ||
        std::memcmp(p + 8, g_run, 16) != 0 || std::memcmp(p + 24, g_manifest, 32) != 0 ||
        Get64(p + 56) != 1 || !SameIdentity(p + 64, g_workerNode, g_workerInc) ||
        Get64(p + 84) != 5 || Get32(p + 92) != 5 || Get32(p + 96) != g_workerPayloadBytes ||
        std::memcmp(p + 100, g_workerDigest, 32) != 0 ||
        std::memcmp(p + 132, receiptHash, 32) != 0 || Get32(p + 164) != 0 ||
        Get64(p + 168) != 0) return false;
    return true;
}

bool PayloadSize(uint16_t kind, uint32_t bytes)
{
    switch (kind)
    {
        case DE_ADMISSION_PREPARED: case DE_ENTRY_MATCHED: case DE_PEER_READY_RECEIVED:
        case DE_GRANT_SENT: case DE_WORKER_STAGED_ACK_SENT: case DE_COORDINATOR_STAGED_ACK_RECEIVED:
        case DE_WORKER_STAGED: case DE_MAIN_AUTHORIZATION_CONSUMED: case DE_MAIN_STARTED:
        case DE_RECORD_CANDIDATE_CLOSED: return bytes == 0;
        case DE_MAIN_RETURNED: case DE_FATAL_NOTICE_PROCESSED: case DE_RUN_ABORT_LATCHED:
        case DE_MAIN_FAILED: case DE_EVIDENCE_OVERFLOW: case DE_EVIDENCE_WRITE_FAILED: return bytes == 4;
        case DE_COORDINATOR_TERMINAL_COMMIT: return bytes == 60;
        case DE_TERMINAL_PREPARE_SENT: return bytes == 152;
        case DE_WORKER_TERMINAL_COMMIT_PREPARED: return bytes == 24;
        case DE_CUSTODY_RECEIPT_SENT: return bytes == 160;
        case DE_TERMINAL_ACK_RECEIVED: return bytes == 176;
        case DE_WORKER_RETIRED: return bytes == 36;
        case DE_CUT_SEALED: return bytes == 132;
        case DE_RECORD_ABORTED: return bytes == 4;
        case DE_POST_RETIREMENT_DISCONNECT: return bytes == 4;
        default: return false;
    }
}

bool LocalEventAllowed(uint16_t kind)
{
    if (g_coordinator)
    {
        switch (kind)
        {
            case DE_ADMISSION_PREPARED: case DE_ENTRY_MATCHED: case DE_PEER_READY_RECEIVED:
            case DE_GRANT_SENT: case DE_COORDINATOR_STAGED_ACK_RECEIVED:
            case DE_MAIN_AUTHORIZATION_CONSUMED: case DE_MAIN_STARTED: case DE_MAIN_RETURNED:
            case DE_COORDINATOR_TERMINAL_COMMIT: case DE_TERMINAL_PREPARE_SENT:
            case DE_CUSTODY_RECEIPT_SENT: case DE_TERMINAL_ACK_RECEIVED: case DE_WORKER_RETIRED:
            case DE_CUT_SEALED: case DE_RECORD_CANDIDATE_CLOSED: case DE_RECORD_ABORTED:
            case DE_FATAL_NOTICE_PROCESSED: case DE_RUN_ABORT_LATCHED: case DE_MAIN_FAILED:
            case DE_EVIDENCE_OVERFLOW: case DE_EVIDENCE_WRITE_FAILED: case DE_POST_RETIREMENT_DISCONNECT:
                return true;
            default: return false;
        }
    }
    switch (kind)
    {
        case DE_ADMISSION_PREPARED: case DE_ENTRY_MATCHED: case DE_WORKER_STAGED_ACK_SENT:
        case DE_WORKER_STAGED: case DE_WORKER_TERMINAL_COMMIT_PREPARED: case DE_RECORD_ABORTED:
        case DE_FATAL_NOTICE_PROCESSED: case DE_RUN_ABORT_LATCHED: case DE_EVIDENCE_OVERFLOW:
        case DE_EVIDENCE_WRITE_FAILED:
            return true;
        default: return false;
    }
}

bool AppendLocalLocked(uint16_t kind, uint64_t epoch, const unsigned char* threadId,
    const unsigned char* objectId, const unsigned char* operationId,
    const unsigned char* payload, uint32_t payloadBytes);

void LatchConflictingTerminalRecordLocked()
{
    if (g_state == State::Written || g_state == State::Failed) return;
    g_aborted = true;
    const uint32_t reasonCode = 9;
    unsigned char reason[4]; Put32(reason, reasonCode);
    const unsigned char zero[16]{};
    AppendLocalLocked(DE_FATAL_NOTICE_PROCESSED, 0, zero, zero, zero, reason, sizeof(reason));
    AppendLocalLocked(DE_RUN_ABORT_LATCHED, 0, zero, zero, zero, reason, sizeof(reason));
    g_state = State::Failed;
}

bool WriteAll(int fd, const unsigned char* bytes, size_t count)
{
    size_t offset = 0;
    while (offset < count)
    {
        ssize_t written = write(fd, bytes + offset, count - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        offset += (size_t)written;
    }
    return true;
}

bool AppendLocalLocked(uint16_t kind, uint64_t epoch, const unsigned char* threadId,
    const unsigned char* objectId, const unsigned char* operationId,
    const unsigned char* payload, uint32_t payloadBytes)
{
    const bool sealedDiagnostic = g_state == State::CoordinatorSealed &&
        (kind == DE_RECORD_CANDIDATE_CLOSED || kind == DE_POST_RETIREMENT_DISCONNECT ||
         kind == DE_FATAL_NOTICE_PROCESSED || kind == DE_RUN_ABORT_LATCHED);
    const bool publishingFailure = g_state == State::Publishing &&
        (kind == DE_FATAL_NOTICE_PROCESSED || kind == DE_RUN_ABORT_LATCHED);
    if ((g_state != State::Active && !(kind == DE_RECORD_ABORTED && g_state == State::Failed) &&
         !sealedDiagnostic && !publishingFailure) ||
        !LocalEventAllowed(kind) || payloadBytes > kEventPayloadLimit ||
        !PayloadSize(kind, payloadBytes) || (payloadBytes != 0 && payload == nullptr) ||
        !threadId || !objectId || !operationId || !AllZero(threadId, 16) ||
        !AllZero(objectId, 16) || !AllZero(operationId, 16) || g_localRecords.size() >= kEventsPerNodeLimit)
        return false;
    if ((kind <= DE_MAIN_STARTED && epoch != 0) ||
        (kind >= DE_MAIN_RETURNED && kind <= DE_TERMINAL_ACK_RECEIVED && epoch != 1) ||
        (kind >= DE_WORKER_RETIRED && kind <= DE_CUT_SEALED && epoch != 1)) return false;
    if (kind != DE_FATAL_NOTICE_PROCESSED && kind != DE_RUN_ABORT_LATCHED &&
        kind != DE_RECORD_ABORTED && kind != DE_POST_RETIREMENT_DISCONNECT &&
        !ExpectedLocalKind(g_localRecords.size(), kind)) return false;
    if (kind == DE_POST_RETIREMENT_DISCONNECT &&
        (g_state != State::CoordinatorSealed || g_localRecords.empty() ||
         Get16(g_localRecords.back().data() + 6) != DE_CUT_SEALED || Get32(payload) != 12)) return false;

    if (kind == DE_MAIN_RETURNED)
    {
        if (Get32(payload) != 0) return false;
        g_resultCode = (int32_t)Get32(payload);
        unsigned char resultBytes[4]; Put32(resultBytes, (uint32_t)g_resultCode);
        if (!Hash(resultBytes, sizeof(resultBytes), g_resultDigest)) return false;
        g_hasResult = true;
    }
    if (kind == DE_COORDINATOR_TERMINAL_COMMIT &&
        (!g_hasResult || Get64(payload) != 1 || Get64(payload + 8) != g_localRecords.size() + 1 ||
         Get64(payload + 16) != 0 || (int32_t)Get32(payload + 24) != g_resultCode ||
         std::memcmp(payload + 28, g_resultDigest, 32) != 0)) return false;
    if (kind == DE_WORKER_TERMINAL_COMMIT_PREPARED &&
        (Get64(payload) != 1 || Get64(payload + 8) != 0 || Get32(payload + 16) != 0 || Get32(payload + 20) != 0))
        return false;
    if (kind == DE_TERMINAL_PREPARE_SENT && !ValidateDctp(payload)) return false;
    if (kind == DE_CUSTODY_RECEIPT_SENT)
    {
        if (!g_custodyReady || !ValidateDccr(payload)) return false;
        std::memcpy(g_custodyReceipt, payload, sizeof(g_custodyReceipt));
        g_custodyReceiptValid = true;
    }
    if (kind == DE_TERMINAL_ACK_RECEIVED && !ValidateDcta(payload)) return false;

    uint64_t mono = 0, wall = 0;
    if (!Times(mono, wall)) return false;
    const uint64_t sequence = g_localRecords.size() + 1;
    std::vector<unsigned char> record(kEventHeaderBytes + payloadBytes, 0);
    Put32(record.data(), (uint32_t)record.size());
    Put16(record.data() + 4, 1);
    Put16(record.data() + 6, kind);
    Put32(record.data() + 8, g_localNode);
    Put64(record.data() + 12, sequence);
    Put64(record.data() + 20, mono);
    Put64(record.data() + 28, wall);
    std::memcpy(record.data() + 36, g_run, sizeof(g_run));
    std::memcpy(record.data() + 52, g_manifest, sizeof(g_manifest));
    std::memcpy(record.data() + 84, g_localInc, sizeof(g_localInc));
    std::memcpy(record.data() + 100, threadId, 16);
    std::memcpy(record.data() + 116, objectId, 16);
    std::memcpy(record.data() + 132, operationId, 16);
    Put64(record.data() + 148, epoch);
    Put32(record.data() + 156, payloadBytes);
    if (payloadBytes != 0) std::memcpy(record.data() + kEventHeaderBytes, payload, payloadBytes);
    g_localRecords.push_back(record);
    g_allRecords.push_back(std::move(record));
    return true;
}

bool BuildArtifact(uint32_t outcome, std::vector<unsigned char>& file)
{
    file.clear();
    file.resize(kHeaderBytes, 0);
    std::memcpy(file.data(), "DCE1", 4);
    Put16(file.data() + 4, 1);
    Put16(file.data() + 6, (uint16_t)kHeaderBytes);
    std::memcpy(file.data() + 8, g_run, 16);
    std::memcpy(file.data() + 24, g_manifest, 32);
    std::memcpy(file.data() + 56, g_topology, 32);
    Put32(file.data() + 88, g_coordNode);
    Put32(file.data() + 92, g_workerNode);
    std::memcpy(file.data() + 96, g_coordInc, 16);
    std::memcpy(file.data() + 112, g_workerInc, 16);
    size_t count = 0;
    for (const auto& record : g_allRecords)
    {
        if (record.size() < kEventHeaderBytes || record.size() > kEventBytesLimit ||
            file.size() > kArtifactBytesLimit - record.size() - kFooterBytes) return false;
        file.insert(file.end(), record.begin(), record.end());
        ++count;
    }
    if (count > 2 * kEventsPerNodeLimit || file.size() + kFooterBytes > kArtifactBytesLimit) return false;
    unsigned char digest[32];
    if (!Hash(file.data(), file.size(), digest)) return false;
    const size_t footer = file.size();
    file.resize(footer + kFooterBytes, 0);
    std::memcpy(file.data() + footer, "DCEF", 4);
    Put16(file.data() + footer + 4, 1);
    Put16(file.data() + footer + 6, (uint16_t)outcome);
    Put64(file.data() + footer + 8, count);
    Put64(file.data() + footer + 16, count);
    std::memcpy(file.data() + footer + 24, digest, sizeof(digest));
    Put64(file.data() + footer + 56, file.size());
    return true;
}

bool WritePending(const std::vector<unsigned char>& bytes, std::string& pending)
{
    if (g_recordPath.empty() || bytes.size() > kArtifactBytesLimit || g_recordPath.size() + 40 >= PATH_MAX)
        return false;
    pending = g_recordPath + ".pending." + std::to_string((long long)getpid());
    int fd = open(pending.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = WriteAll(fd, bytes.data(), bytes.size());
    if (close(fd) != 0) ok = false;
    return ok;
}
}

extern "C" bool DistributedEvidenceConfigure(const unsigned char runId[16],
    const unsigned char manifestSha256[32], const unsigned char topologySha256[32],
    uint32_t coordinatorNode, const unsigned char coordinatorIncarnation[16],
    uint32_t workerNode, const unsigned char workerIncarnation[16],
    uint32_t localNode, const unsigned char localIncarnation[16],
    const char* absoluteRecordPath, bool coordinator, bool emptyProbe)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_state != State::Empty || !runId || !manifestSha256 || !topologySha256 ||
        !coordinatorIncarnation || !workerIncarnation || !localIncarnation ||
        coordinatorNode == 0 || workerNode == 0 || coordinatorNode == workerNode ||
        (localNode != coordinatorNode && localNode != workerNode) ||
        ((localNode == coordinatorNode) != coordinator) ||
        (coordinator && (!absoluteRecordPath || absoluteRecordPath[0] != '/')) ||
        (!coordinator && absoluteRecordPath != nullptr) || !emptyProbe) return false;
    std::memcpy(g_run, runId, 16);
    std::memcpy(g_manifest, manifestSha256, 32);
    std::memcpy(g_topology, topologySha256, 32);
    std::memcpy(g_coordInc, coordinatorIncarnation, 16);
    std::memcpy(g_workerInc, workerIncarnation, 16);
    std::memcpy(g_localInc, localIncarnation, 16);
    g_coordNode = coordinatorNode;
    g_workerNode = workerNode;
    g_localNode = localNode;
    g_coordinator = coordinator;
    g_emptyProbe = emptyProbe;
    if (coordinator) g_recordPath = absoluteRecordPath;
    g_state = State::Active;
    return true;
}

extern "C" bool DistributedEvidenceRecord(uint16_t eventKind, uint64_t epoch,
    const unsigned char logicalThreadId[16], const unsigned char logicalObjectId[16],
    const unsigned char operationId[16], const unsigned char* payload, uint32_t payloadBytes)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (!logicalThreadId || !logicalObjectId || !operationId) return false;
    if (g_coordinator && (eventKind == DE_CUSTODY_RECEIPT_SENT || eventKind == DE_TERMINAL_ACK_RECEIVED))
    {
        const size_t index = eventKind == DE_CUSTODY_RECEIPT_SENT ? 10 : 11;
        if (g_localRecords.size() > index && Get16(g_localRecords[index].data() + 6) == eventKind)
        {
            const std::vector<unsigned char>& previous = g_localRecords[index];
            const uint32_t previousBytes = Get32(previous.data() + 156);
            const bool exact = epoch == 1 && payload && payloadBytes == previousBytes &&
                AllZero(logicalThreadId, 16) && AllZero(logicalObjectId, 16) &&
                AllZero(operationId, 16) && previousBytes == payloadBytes &&
                std::memcmp(previous.data() + kEventHeaderBytes, payload, payloadBytes) == 0;
            if (!exact) LatchConflictingTerminalRecordLocked();
            return exact;
        }
    }
    if (eventKind == DE_WORKER_TERMINAL_COMMIT_PREPARED &&
        (!g_coordinator && g_localRecords.size() != 4)) return false;
    return AppendLocalLocked(eventKind, epoch, logicalThreadId, logicalObjectId,
        operationId, payload, payloadBytes);
}

extern "C" bool DistributedEvidenceCanCommitWorker(void)
{
    std::lock_guard<std::mutex> lock(g_lock);
    return !g_coordinator && g_emptyProbe && !g_aborted && g_state == State::Active && g_localRecords.size() == 4 &&
        Get16(g_localRecords.back().data() + 6) == DE_WORKER_STAGED;
}

extern "C" bool DistributedEvidenceValidateTerminalPrepare(const unsigned char* prepare, size_t bytes)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_coordinator || !g_emptyProbe || g_aborted || !prepare || bytes != sizeof(g_terminalPrepare)) return false;
    if (g_terminalPrepareValid)
        return (g_state == State::WorkerFrozen || g_state == State::WorkerRetired) &&
            std::memcmp(g_terminalPrepare, prepare, sizeof(g_terminalPrepare)) == 0;
    if (g_state != State::Active || g_localRecords.size() != 4 || !ValidateDctp(prepare)) return false;
    std::memcpy(g_terminalPrepare, prepare, sizeof(g_terminalPrepare));
    g_terminalPrepareValid = true;
    return true;
}

extern "C" bool DistributedEvidenceRetireWorker(void)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_coordinator || g_aborted || !g_custodyReceiptValid || g_state != State::WorkerFrozen) return false;
    g_state = State::WorkerRetired;
    return true;
}

extern "C" bool DistributedEvidenceAcceptWorkerRecord(const unsigned char* record, size_t bytes)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (!g_coordinator || g_state != State::Active || !record || bytes < kEventHeaderBytes ||
        bytes > kEventBytesLimit || Get32(record) != bytes || Get16(record + 4) != 1) return false;
    const uint16_t kind = Get16(record + 6);
    const uint32_t payloadBytes = Get32(record + 156);
    if (bytes != kEventHeaderBytes + payloadBytes ||
        payloadBytes > kEventPayloadLimit || !PayloadSize(kind, payloadBytes) ||
        Get32(record + 8) != g_workerNode || Get64(record + 12) == 0 ||
        std::memcmp(record + 36, g_run, 16) != 0 || std::memcmp(record + 52, g_manifest, 32) != 0 ||
        std::memcmp(record + 84, g_workerInc, 16) != 0 || !AllZero(record + 100, 48)) return false;
    const uint64_t seq = Get64(record + 12);
    if (seq <= g_workerRecords.size())
        return seq > 0 && g_workerRecords[seq - 1].size() == bytes &&
            std::memcmp(g_workerRecords[seq - 1].data(), record, bytes) == 0;
    if (seq != g_workerRecords.size() + 1 || seq > kEventsPerNodeLimit) return false;
    const uint16_t expected[] = { DE_ADMISSION_PREPARED, DE_ENTRY_MATCHED, DE_WORKER_STAGED_ACK_SENT,
                                  DE_WORKER_STAGED, DE_WORKER_TERMINAL_COMMIT_PREPARED };
    if (seq > sizeof(expected) / sizeof(expected[0]) || kind != expected[seq - 1]) return false;
    if ((seq < 5 && Get64(record + 148) != 0) || (seq == 5 && Get64(record + 148) != 1)) return false;
    if (kind == DE_WORKER_TERMINAL_COMMIT_PREPARED &&
        (payloadBytes != 24 || Get64(record + kEventHeaderBytes) != 1 ||
         Get64(record + kEventHeaderBytes + 8) != 0 ||
         Get32(record + kEventHeaderBytes + 16) != 0 || Get32(record + kEventHeaderBytes + 20) != 0)) return false;
    if (Get64(record + 20) == 0 || Get64(record + 28) == 0 ||
        (seq > 1 && Get64(record + 20) < g_lastMonotonic[1])) return false;
    g_lastMonotonic[1] = Get64(record + 20);
    g_workerRecords.emplace_back(record, record + bytes);
    g_allRecords.emplace_back(record, record + bytes);
    return true;
}

extern "C" bool DistributedEvidenceWorkerCustodyReceiptMatches(const unsigned char* p, size_t n)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_coordinator || !p || n != sizeof(g_custodyReceipt)) return false;
    if (g_custodyReceiptValid)
        return (g_state == State::WorkerFrozen || g_state == State::WorkerRetired) &&
            std::memcmp(g_custodyReceipt, p, sizeof(g_custodyReceipt)) == 0;
    if (g_state != State::WorkerFrozen ||
        std::memcmp(p, "DCCR", 4) != 0 || Get16(p + 4) != 1 || Get16(p + 6) != 160 ||
        std::memcmp(p + 8, g_run, 16) != 0 || std::memcmp(p + 24, g_manifest, 32) != 0 ||
        Get64(p + 56) != 1 || !SameIdentity(p + 64, g_coordNode, g_coordInc) ||
        !SameIdentity(p + 84, g_workerNode, g_workerInc) || Get64(p + 104) != g_localRecords.size() ||
        Get32(p + 112) != g_localRecords.size() || Get32(p + 116) != g_workerPayloadBytes ||
        std::memcmp(p + 120, g_workerDigest, 32) != 0 || !AllZero(p + 152, 8) || !ValidateDccr(p)) return false;
    std::memcpy(g_custodyReceipt, p, sizeof(g_custodyReceipt));
    g_custodyReceiptValid = true;
    return true;
}

extern "C" bool DistributedEvidenceFreezeWorker(uint64_t* lastSequence, uint32_t* eventCount,
    uint32_t* payloadBytes, unsigned char digest[32], unsigned char* records, size_t capacity)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_coordinator || !g_emptyProbe || g_aborted || g_state != State::Active || g_localRecords.size() != 5 ||
        Get16(g_localRecords.back().data() + 6) != DE_WORKER_TERMINAL_COMMIT_PREPARED ||
        !lastSequence || !eventCount || !payloadBytes || !digest || !records) return false;
    size_t total = 0;
    for (const auto& r : g_localRecords) total += r.size();
    if (total > kWorkerBytesLimit || total > capacity) return false;
    size_t offset = 0;
    for (const auto& r : g_localRecords) { std::memcpy(records + offset, r.data(), r.size()); offset += r.size(); }
    if (!Hash(records, total, g_workerDigest)) return false;
    g_workerPayloadBytes = (uint32_t)total;
    std::memcpy(digest, g_workerDigest, 32);
    *lastSequence = g_localRecords.size();
    *eventCount = (uint32_t)g_localRecords.size();
    *payloadBytes = (uint32_t)total;
    g_state = State::WorkerFrozen;
    return true;
}

extern "C" bool DistributedEvidenceCoordinatorCustodyReady(uint64_t lastSequence,
    uint32_t eventCount, uint32_t payloadBytes, const unsigned char digest[32])
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (!g_coordinator || g_state != State::Active || !digest || g_workerRecords.size() != 5 ||
        lastSequence != 5 || eventCount != g_workerRecords.size()) return false;
    size_t total = 0;
    std::vector<unsigned char> bytes;
    for (const auto& r : g_workerRecords) { total += r.size(); bytes.insert(bytes.end(), r.begin(), r.end()); }
    unsigned char actual[32];
    if (total != payloadBytes || total > kWorkerBytesLimit || !Hash(bytes.data(), bytes.size(), actual) ||
        std::memcmp(actual, digest, 32) != 0) return false;
    g_workerPayloadBytes = (uint32_t)total;
    std::memcpy(g_workerDigest, actual, 32);
    g_custodyReady = true;
    return true;
}

extern "C" bool DistributedEvidenceCoordinatorSeal(uint64_t workerFrontier,
    const unsigned char workerDigest[32], int32_t resultCode, const unsigned char resultDigest[32])
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (!g_coordinator || g_state != State::Active || g_aborted || !g_custodyReady || !g_hasResult ||
        g_localRecords.size() != 12 || Get16(g_localRecords.back().data() + 6) != DE_TERMINAL_ACK_RECEIVED ||
        workerFrontier != 5 || !workerDigest || std::memcmp(workerDigest, g_workerDigest, 32) != 0 ||
        !resultDigest || resultCode != g_resultCode)
        return false;
    unsigned char resultBytes[4], expectedResult[32];
    Put32(resultBytes, (uint32_t)resultCode);
    if (!Hash(resultBytes, sizeof(resultBytes), expectedResult) || std::memcmp(expectedResult, resultDigest, 32) != 0)
        return false;
    unsigned char retire[36]{};
    Put64(retire, 1); Put32(retire + 8, g_workerNode); std::memcpy(retire + 12, g_workerInc, 16); Put64(retire + 28, workerFrontier);
    const unsigned char zero[16]{};
    if (!AppendLocalLocked(DE_WORKER_RETIRED, 1, zero, zero, zero, retire, sizeof(retire))) return false;
    unsigned char seal[132]{};
    Put64(seal, 1); Put32(seal + 8, g_coordNode); std::memcpy(seal + 12, g_coordInc, 16);
    Put64(seal + 28, g_localRecords.size() + 1); Put32(seal + 36, g_workerNode);
    std::memcpy(seal + 40, g_workerInc, 16); Put64(seal + 56, workerFrontier);
    Put32(seal + 64, (uint32_t)resultCode); std::memcpy(seal + 68, resultDigest, 32);
    std::memcpy(seal + 100, workerDigest, 32);
    if (!AppendLocalLocked(DE_CUT_SEALED, 1, zero, zero, zero, seal, sizeof(seal))) return false;
    g_state = State::CoordinatorSealed;
    return true;
}

extern "C" bool DistributedEvidenceWriteRecord(uint32_t outcome)
{
    std::vector<unsigned char> bytes;
    std::string pending;
    {
        std::lock_guard<std::mutex> lock(g_lock);
        if (!g_coordinator || (outcome != 1 && outcome != 2 && outcome != 3) || g_state == State::Written) return false;
        if (outcome == 3)
        {
            if (g_state != State::CoordinatorSealed || g_aborted) return false;
            const unsigned char zero[16]{};
            if (!AppendLocalLocked(DE_RECORD_CANDIDATE_CLOSED, 1, zero, zero, zero, nullptr, 0)) return false;
        }
        else
        {
            if (g_state == State::CoordinatorSealed) return false;
            bool fatalSeen = false, abortSeen = false;
            uint32_t fatalReason = 0, abortReason = 0;
            for (const auto& record : g_localRecords)
            {
                const uint16_t kind = Get16(record.data() + 6);
                if ((kind != DE_FATAL_NOTICE_PROCESSED && kind != DE_RUN_ABORT_LATCHED) ||
                    Get32(record.data() + 156) != 4) continue;
                const uint32_t reason = Get32(record.data() + kEventHeaderBytes);
                if (kind == DE_FATAL_NOTICE_PROCESSED) { fatalSeen = true; fatalReason = reason; }
                if (kind == DE_RUN_ABORT_LATCHED) { abortSeen = true; abortReason = reason; }
            }
            if (!fatalSeen || !abortSeen || fatalReason != abortReason) return false;
            g_aborted = true;
            unsigned char reason[4]; Put32(reason, fatalReason);
            const unsigned char zero[16]{};
            if (!AppendLocalLocked(DE_RECORD_ABORTED, 1, zero, zero, zero, reason, 4)) return false;
        }
        if (!BuildArtifact(outcome, bytes)) return false;
        g_state = outcome == 3 ? State::Publishing : State::PublishingAbort;
    }
    if (!WritePending(bytes, pending))
    {
        std::lock_guard<std::mutex> lock(g_lock);
        g_aborted = true;
        g_state = State::Failed;
        return false;
    }
    bool published = false;
    {
        std::lock_guard<std::mutex> lock(g_lock);
        const State expected = outcome == 3 ? State::Publishing : State::PublishingAbort;
        if (g_state == expected && (outcome != 3 || !g_aborted) && link(pending.c_str(), g_recordPath.c_str()) == 0)
        {
            g_state = State::Written;
            published = true;
        }
        else
        {
            g_aborted = true;
            g_state = State::Failed;
        }
    }
    if (published) unlink(pending.c_str());
    return published;
}

extern "C" bool DistributedEvidenceIsEmptyProbe(void)
{
    std::lock_guard<std::mutex> lock(g_lock);
    return g_emptyProbe && g_state != State::Empty;
}

extern "C" bool DistributedEvidenceIsConfigured(void)
{
    std::lock_guard<std::mutex> lock(g_lock);
    return g_state != State::Empty;
}

extern "C" void DistributedEvidenceAbort(uint32_t reason)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (g_state == State::Empty || g_state == State::Written || g_state == State::Failed) return;
    g_aborted = true;
    unsigned char value[4]; Put32(value, reason);
    const unsigned char zero[16]{};
    AppendLocalLocked(DE_FATAL_NOTICE_PROCESSED, 0, zero, zero, zero, value, sizeof(value));
    AppendLocalLocked(DE_RUN_ABORT_LATCHED, 0, zero, zero, zero, value, sizeof(value));
    g_state = State::Failed;
}

extern "C" void DistributedEvidenceTransportFailure(uint32_t reason)
{
    std::lock_guard<std::mutex> lock(g_lock);
    if (reason == 12 && !g_coordinator && g_state == State::WorkerRetired) return;
    // The native transport reserves 12 for a narrowly classified physical
    // peer disconnect. It is benign only after the coordinator has sealed.
    if (reason == 12 && g_coordinator && g_state == State::CoordinatorSealed)
    {
        g_transportDisconnected = true;
        unsigned char payload[4]; Put32(payload, reason);
        const unsigned char zero[16]{};
        AppendLocalLocked(DE_POST_RETIREMENT_DISCONNECT, 1, zero, zero, zero, payload, sizeof(payload));
        return;
    }
    if (reason == 12 && g_coordinator && g_state == State::Publishing) return;
    if (g_state == State::Empty || g_state == State::Written || g_state == State::Failed) return;
    g_aborted = true;
    const unsigned char zero[16]{};
    unsigned char payload[4]; Put32(payload, reason);
    AppendLocalLocked(DE_FATAL_NOTICE_PROCESSED, 0, zero, zero, zero, payload, sizeof(payload));
    AppendLocalLocked(DE_RUN_ABORT_LATCHED, 0, zero, zero, zero, payload, sizeof(payload));
    g_state = State::Failed;
}

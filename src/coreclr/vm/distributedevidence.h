#ifndef DISTRIBUTED_EVIDENCE_H
#define DISTRIBUTED_EVIDENCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum DistributedEvidenceEventKind
{
    DE_ADMISSION_PREPARED = 1,
    DE_ENTRY_MATCHED = 2,
    DE_PEER_READY_RECEIVED = 3,
    DE_GRANT_SENT = 4,
    DE_WORKER_STAGED_ACK_SENT = 5,
    DE_COORDINATOR_STAGED_ACK_RECEIVED = 6,
    DE_WORKER_STAGED = 7,
    DE_MAIN_AUTHORIZATION_CONSUMED = 8,
    DE_MAIN_STARTED = 9,
    DE_MAIN_RETURNED = 10,
    DE_COORDINATOR_TERMINAL_COMMIT = 11,
    DE_TERMINAL_PREPARE_SENT = 12,
    DE_WORKER_TERMINAL_COMMIT_PREPARED = 13,
    DE_CUSTODY_RECEIPT_SENT = 14,
    DE_TERMINAL_ACK_RECEIVED = 15,
    DE_FATAL_NOTICE_PROCESSED = 16,
    DE_RUN_ABORT_LATCHED = 17,
    DE_WORKER_RETIRED = 18,
    DE_CUT_SEALED = 19,
    DE_RECORD_CANDIDATE_CLOSED = 20,
    DE_RECORD_ABORTED = 21,
    DE_MAIN_FAILED = 22,
    DE_EVIDENCE_OVERFLOW = 23,
    DE_EVIDENCE_WRITE_FAILED = 24,
    DE_POST_RETIREMENT_DISCONNECT = 25
};

bool DistributedEvidenceConfigure(const unsigned char runId[16],
    const unsigned char manifestSha256[32], const unsigned char topologySha256[32],
    uint32_t coordinatorNode, const unsigned char coordinatorIncarnation[16],
    uint32_t workerNode, const unsigned char workerIncarnation[16],
    uint32_t localNode, const unsigned char localIncarnation[16],
    const char* absoluteRecordPath, bool coordinator, bool emptyProbe);
bool DistributedEvidenceRecord(uint16_t eventKind, uint64_t epoch,
    const unsigned char logicalThreadId[16], const unsigned char logicalObjectId[16],
    const unsigned char operationId[16], const unsigned char* payload, uint32_t payloadBytes);
bool DistributedEvidenceCanCommitWorker(void);
bool DistributedEvidenceValidateTerminalPrepare(const unsigned char* prepare, size_t bytes);
bool DistributedEvidenceRetireWorker(void);
bool DistributedEvidenceAcceptWorkerRecord(const unsigned char* record, size_t bytes);
bool DistributedEvidenceWorkerCustodyReceiptMatches(const unsigned char* receipt, size_t bytes);
bool DistributedEvidenceFreezeWorker(uint64_t* lastSequence, uint32_t* eventCount,
    uint32_t* payloadBytes, unsigned char digest[32],
    unsigned char* records, size_t capacity);
bool DistributedEvidenceCoordinatorCustodyReady(uint64_t lastSequence,
    uint32_t eventCount, uint32_t payloadBytes, const unsigned char digest[32]);
bool DistributedEvidenceCoordinatorSeal(uint64_t workerFrontier,
    const unsigned char workerDigest[32], int32_t resultCode,
    const unsigned char resultDigest[32]);
bool DistributedEvidenceWriteRecord(uint32_t outcome);
bool DistributedEvidenceIsEmptyProbe(void);
bool DistributedEvidenceIsConfigured(void);
void DistributedEvidenceAbort(uint32_t reason);
void DistributedEvidenceTransportFailure(uint32_t reason);

#ifdef __cplusplus
}
#endif

#endif

#ifndef DISTRIBUTED_ADMISSION_H
#define DISTRIBUTED_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
struct DistributedIdentityContext;
extern "C" {
#endif

int DistributedAdmissionPrepare(const char* absoluteAppPath);
bool DistributedAdmissionIsEnabled(void);
struct DistributedAdmissionJournalContext
{
    unsigned char run[16];
    unsigned char manifestSha256[32];
    unsigned localNode;
    unsigned peerNode;
    unsigned char localIncarnation[16];
    unsigned char peerIncarnation[16];
    char manifestPath[512];
};
bool DistributedAdmissionCopyJournalContext(DistributedAdmissionJournalContext* context);

struct DistributedAdmissionThreadIdentity
{
    unsigned char run[16];
    unsigned char runManifestSha256[32];
    unsigned char buildManifestSha256[32];
    unsigned char memberIncarnations[2][16];
    unsigned localNode;
};
// Closed positive Thread profile only; returns immutable admission facts, not a terminal verdict.
bool DistributedAdmissionCopyThreadIdentity(DistributedAdmissionThreadIdentity* context);
bool DistributedAdmissionCheckEnvironment(void);
bool DistributedAdmissionIsEmptyProbe(void);
bool DistributedAdmissionIsIdentityProbe(void);
bool DistributedAdmissionIsAccessProbe(void);
bool DistributedAdmissionIsPublicationProbe(void);
bool DistributedAdmissionIsThreadProbe(void);
bool DistributedAdmissionIsThreadNegativeProbe(void);
bool DistributedAdmissionIdentityContext(DistributedIdentityContext* context);
int DistributedAdmissionIdentityWorker(int (*processGraph)(const unsigned char*, int, unsigned char*, int));
bool DistributedAdmissionConfirmEntry(bool emptyProfileProof);
bool DistributedAdmissionRecordMainStarted(void);
int DistributedAdmissionCompleteMain(int32_t resultCode);
bool DistributedAdmissionMatchEntry(const unsigned char* flatPe, size_t peLen,
    const unsigned char* mvid16, unsigned typeToken, unsigned methodToken,
    const unsigned char* sig, size_t sigLen, const unsigned char* il, size_t ilLen);
int DistributedAdmissionBarrier(void);
bool DistributedAdmissionConsumeMain(void);
bool DistributedAdmissionCheckMaps(void);
bool DistributedAdmissionCheckCompiler(const void* getJitSymbol);
void DistributedAdmissionStop(void);

#ifdef __cplusplus
}
#endif

#endif

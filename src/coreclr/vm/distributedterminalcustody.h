// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DCG01_DISTRIBUTED_TERMINAL_CUSTODY_H
#define DCG01_DISTRIBUTED_TERMINAL_CUSTODY_H

#include "distributedterminalpreimages.h"

// Closed Thread-profile transport custody. Authentication and source facts are
// supplied by the existing runtime channel owner; this is not a terminal seal.
namespace DCG01Custody
{
constexpr size_t MaxWire = 4096, HeaderBytes = 16, AckBytes = 40;
struct Bundle { size_t length; unsigned char bytes[MaxWire]; };
struct WorkerPreimage
{
    size_t commitmentLength, evidenceLength;
    unsigned char commitment[2048], evidence[256];
};
struct Receiver
{
    bool failed, hasCustody;
    Bundle received;
};
enum class Accepted { Failed, New, Duplicate };

inline void Put32(unsigned char* p, uint32_t value)
{ for (size_t i=0;i<4;++i) p[i]=static_cast<unsigned char>(value>>(8*i)); }
inline bool IsBundle(const unsigned char* bytes,size_t length)
{ return bytes!=nullptr && length>=4 && memcmp(bytes,"DCB1",4)==0; }
inline bool IsAck(const unsigned char* bytes,size_t length)
{ return bytes!=nullptr && length>=4 && memcmp(bytes,"DCK1",4)==0; }

inline bool EncodeBundle(const unsigned char* commitment,size_t commitmentLength,
                         const unsigned char* evidence,size_t evidenceLength,Bundle* output)
{
    if (!output || !commitment || !evidence || commitmentLength==0 || evidenceLength==0 ||
        commitmentLength>MaxWire-HeaderBytes || evidenceLength>MaxWire-HeaderBytes-commitmentLength)
        return false;
    Bundle local{};
    memcpy(local.bytes,"DCB1",4); Put32(local.bytes+4,1);
    Put32(local.bytes+8,static_cast<uint32_t>(commitmentLength));
    Put32(local.bytes+12,static_cast<uint32_t>(evidenceLength));
    memcpy(local.bytes+HeaderBytes,commitment,commitmentLength);
    memcpy(local.bytes+HeaderBytes+commitmentLength,evidence,evidenceLength);
    local.length=HeaderBytes+commitmentLength+evidenceLength;
    *output=local;
    return true;
}

inline bool MakeAck(const Bundle& bundle,DCG01Preimage::HashFunction hash,unsigned char output[AckBytes])
{
    if (!output || bundle.length<=HeaderBytes || bundle.length>MaxWire || !IsBundle(bundle.bytes,bundle.length))
        return false;
    unsigned char local[AckBytes]{};
    memcpy(local,"DCK1",4); Put32(local+4,1);
    if (!DCG01Preimage::Hash(hash,bundle.bytes,bundle.length,local+8)) return false;
    memcpy(output,local,AckBytes);
    return true;
}

// Match exact canonical expectations, then own the actual received bytes before ACK.
// Caller serializes this state; rejection latches failure and never replaces custody.
inline Accepted Accept(Receiver* state,const Bundle& expected,const unsigned char* wire,size_t length,
                       DCG01Preimage::HashFunction hash,unsigned char ack[AckBytes])
{
    if (!state) return Accepted::Failed;
    if (state->failed) return Accepted::Failed;
    unsigned char localAck[AckBytes]{};
    if (!wire || !ack || expected.length<=HeaderBytes || expected.length>MaxWire ||
        length!=expected.length || memcmp(wire,expected.bytes,length)!=0 ||
        !MakeAck(expected,hash,localAck) ||
        (state->hasCustody && (state->received.length!=length || memcmp(state->received.bytes,wire,length)!=0)))
    { state->failed=true; return Accepted::Failed; }
    Accepted disposition=state->hasCustody ? Accepted::Duplicate : Accepted::New;
    if (!state->hasCustody)
    {
        memcpy(state->received.bytes,wire,length);
        state->received.length=length;
        state->hasCustody=true;
    }
    memcpy(ack,localAck,AckBytes);
    return disposition;
}

inline bool VerifyAck(const Bundle& sent,const unsigned char* wire,size_t length,DCG01Preimage::HashFunction hash)
{
    unsigned char expected[AckBytes]{};
    return wire && length==AckBytes && MakeAck(sent,hash,expected) && memcmp(wire,expected,AckBytes)==0;
}

// Derive the only permitted worker contribution from admitted identity and the
// coordinator's already-validated completion facts. No untrusted JSON is parsed.
inline bool BuildExpectedWorker(const DCG01Preimage::Identity& identity,
                                const DCG01Preimage::LogicalId& joined,uint64_t operations,
                                uint64_t authority,uint64_t publications,
                                DCG01Preimage::HashFunction hash,WorkerPreimage* output)
{
    using namespace DCG01Preimage;
    if (!output || !hash || !ValidIdentity(identity) || !Nonzero(identity.runId,16) ||
        !Nonzero(identity.buildDigest,32) || !Nonzero(identity.runManifestDigest,32) ||
        !Nonzero(identity.incarnation[0],16) || !Nonzero(identity.incarnation[1],16) ||
        !ValidLogical(identity,joined,1) || joined.bytes[36]!=1 ||
        Nonzero(joined.bytes+37,7) || operations==0 || operations>2048 ||
        authority<operations || authority>2048 || publications!=1) return false;
    Participant participant{};
    participant.memberId=2; participant.snapshotId=1;
    Prepared& prepared=participant.prepared;
    prepared.terminalEpoch=1; prepared.lastOperation=operations;
    prepared.authorityFrontier=authority; prepared.publicationFrontier=publications;
    prepared.joinedCount=1; prepared.joinedThreadIds[0]=joined;
    prepared.evidenceArtifactId=3;
    if (!Hash(hash,nullptr,0,prepared.evidenceDigest)) return false;
    unsigned char roots[512]{},rootDigest[32]{}; size_t rootLength=0;
    if (!RootInventory(identity,participant,hash,roots,sizeof(roots),&rootLength,rootDigest)) return false;
    memcpy(prepared.rootInventoryDigest,rootDigest,32);
    WorkerPreimage local{};
    DC022Canonical::Writer evidence(local.evidence,sizeof(local.evidence));
    if (!evidence.BeginObject() || !evidence.Key("admission_generation") || !evidence.UInt(2) ||
        !evidence.Key("application_output") || !evidence.Null() ||
        !evidence.Key("root_inventory_sha256") || !evidence.Hex(rootDigest,32) ||
        !evidence.Key("schema") || !evidence.String("dcg01-closed-thread-evidence") ||
        !evidence.Key("version") || !evidence.UInt(1) || !evidence.EndObject() || !evidence.Finish()) return false;
    local.evidenceLength=evidence.Size();
    prepared.evidenceBytes=local.evidence; prepared.evidenceLength=local.evidenceLength;
    if (!Hash(hash,local.evidence,local.evidenceLength,prepared.evidenceDigest)) return false;
    unsigned char digest[32]{};
    if (!EncodeParticipant(identity,participant,hash,local.commitment,sizeof(local.commitment),
                           &local.commitmentLength,digest)) return false;
    *output=local;
    return true;
}
}
#endif

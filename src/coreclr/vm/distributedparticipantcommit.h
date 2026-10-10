// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DCG01_DISTRIBUTED_PARTICIPANT_COMMIT_H
#define DCG01_DISTRIBUTED_PARTICIPANT_COMMIT_H
#include "distributedterminalcustody.h"

namespace DCG01Commit
{
constexpr size_t HeaderBytes = 8, MaxWire = 4096;
struct Frame { size_t length = 0; unsigned char bytes[MaxWire]{}; };
inline bool IsFrame(const unsigned char* bytes,size_t length)
{ return bytes && length >= HeaderBytes && !memcmp(bytes,"DCM1",4); }
inline bool Encode(const DCG01Custody::Bundle& custody,Frame* output)
{
    if (!output || custody.length <= DCG01Custody::HeaderBytes || custody.length > MaxWire - HeaderBytes ||
        !DCG01Custody::IsBundle(custody.bytes,custody.length)) return false;
    Frame frame{};memcpy(frame.bytes,"DCM1",4);DCG01Custody::Put32(frame.bytes+4,1);
    memcpy(frame.bytes+HeaderBytes,custody.bytes,custody.length);frame.length=HeaderBytes+custody.length;
    *output=frame;return true;
}

// Caller holds the participant failure serializer and has established the closed
// application/root cut. Only an exact custody ACK can make this transition.
class Worker
{
    Frame committed;
public:
    bool IsCommitted() const { return committed.length != 0; }
    bool Commit(const DCG01Preimage::Identity& identity,uint64_t operations,uint64_t authority,uint64_t publications,
                const DCG01Custody::Bundle& sent,const unsigned char* ack,size_t ackLength,
                DCG01Preimage::HashFunction hash,Frame* output)
    {
        if (!output) return false;
        DCG01Preimage::LogicalId joined{};memcpy(joined.bytes,identity.runId,16);
        DCG01Custody::Put32(joined.bytes+16,1);memcpy(joined.bytes+20,identity.incarnation[0],16);joined.bytes[36]=1;
        DCG01Custody::WorkerPreimage preimage{};DCG01Custody::Bundle expected{};Frame frame{};
        if (!DCG01Custody::BuildExpectedWorker(identity,joined,operations,authority,publications,hash,&preimage) ||
            !DCG01Custody::EncodeBundle(preimage.commitment,preimage.commitmentLength,preimage.evidence,preimage.evidenceLength,&expected) ||
            sent.length != expected.length || memcmp(sent.bytes,expected.bytes,expected.length) ||
            !DCG01Custody::VerifyAck(sent,ack,ackLength,hash) || !Encode(sent,&frame) ||
            (IsCommitted() && (committed.length != frame.length || memcmp(committed.bytes,frame.bytes,frame.length)))) return false;
        // No operation after this assignment can fail or reopen application work.
        if (!IsCommitted()) committed=frame;
        *output=committed;return true;
    }
};

class Receipt
{
    Frame received;
public:
    bool HasCommitment() const { return received.length != 0; }
    bool Accept(const DCG01Custody::Bundle& custody,const unsigned char* wire,size_t length)
    {
        Frame expected{};
        if (!wire || !Encode(custody,&expected) || length != expected.length || memcmp(wire,expected.bytes,length) ||
            (HasCommitment() && (received.length != length || memcmp(received.bytes,wire,length)))) return false;
        if (!HasCommitment()) { memcpy(received.bytes,wire,length);received.length=length; }
        return true;
    }
};
}
#endif

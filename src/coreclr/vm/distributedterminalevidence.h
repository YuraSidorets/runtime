// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DISTRIBUTED_TERMINAL_EVIDENCE_H
#define DISTRIBUTED_TERMINAL_EVIDENCE_H
#include "distributedthreadterminal.h"
#include "raw_frame_custody_path.h"
#include <memory>
#include <new>

namespace DCG01TerminalFiles
{
inline bool Matches(const DistributedAdmissionThreadIdentity& id,const DistributedAdmissionJournalContext& context)
{
    return (id.localNode==1 || id.localNode==2) && context.localNode==id.localNode && context.peerNode==3-id.localNode &&
        !memcmp(id.run,context.run,16) && !memcmp(id.runManifestSha256,context.manifestSha256,32) &&
        !memcmp(id.memberIncarnations[id.localNode-1],context.localIncarnation,16) &&
        !memcmp(id.memberIncarnations[2-id.localNode],context.peerIncarnation,16);
}
inline bool Name(const DistributedAdmissionThreadIdentity& id,const char* suffix,char* name,size_t capacity)
{
    if(id.localNode!=1 && id.localNode!=2) return false;
    char run[33]{},inc[33]{};const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<16;++i)
    {
        run[2*i]=digits[id.run[i]>>4];run[2*i+1]=digits[id.run[i]&15];
        inc[2*i]=digits[id.memberIncarnations[id.localNode-1][i]>>4];inc[2*i+1]=digits[id.memberIncarnations[id.localNode-1][i]&15];
    }
    const int n=snprintf(name,capacity,"dcg01-%s-%s.%s",run,inc,suffix);
    return n>0 && static_cast<size_t>(n)<capacity && DCG01Record::ValidName(name);
}
inline bool FileWitness(DC022Canonical::Writer& w,const char* name,const DCG01Record::Witness& v)
{
    return w.BeginObject() && w.Key("directory_device") && w.UInt(v.directoryDevice) &&
        w.Key("directory_flushed") && w.Boolean(v.directoryFlushed) && w.Key("directory_inode") && w.UInt(v.directoryInode) &&
        w.Key("error_number") && w.Int(v.errorNumber) && w.Key("failure") && w.UInt(static_cast<unsigned>(v.failure)) &&
        w.Key("file_device") && w.UInt(v.fileDevice) && w.Key("file_flushed") && w.Boolean(v.fileFlushed) &&
        w.Key("file_inode") && w.UInt(v.fileInode) && w.Key("length") && w.UInt(v.length) &&
        w.Key("name") && w.String(name,strlen(name)) && w.Key("readback_matched") && w.Boolean(v.readbackMatched) &&
        w.Key("renamed") && w.Boolean(v.renamed) && w.Key("sha256") && w.Hex(v.digest,32) &&
        w.Key("written") && w.UInt(v.written) && w.EndObject();
}

// The runtime caller has joined the transport/service before entering this helper.
// All filesystem operations occur outside the terminal failure mutex.
inline DCG01Terminal::PublicationResult Publish(DCG01Terminal::FailureOrder& order,const DistributedAdmissionJournalContext& context)
{
    using Result=DCG01Terminal::PublicationResult;
    DCG01Terminal::FailureSnapshot state{};
    if(!order.Copy(&state) || state.failed || state.identity.localNode!=1 || !Matches(state.identity,context))
    {order.Fail(DCG01Terminal::Origin::Evidence,17,"terminal-file-identity");return Result::Failed;}
    std::unique_ptr<DCG01Events::SealArtifacts> seal(new(std::nothrow) DCG01Events::SealArtifacts);
    std::unique_ptr<unsigned char[]> trace(new(std::nothrow) unsigned char[DCG01Events::Stream::MaxBytes]);
    std::unique_ptr<unsigned char[]> readback(new(std::nothrow) unsigned char[DCG01Events::Stream::MaxBytes]);
    if(!seal || !trace || !readback || !order.BeginRecordPublication(seal.get()))
    {order.Fail(DCG01Terminal::Origin::Evidence,18,"terminal-file-allocation-or-start");return Result::Failed;}
    int directory=dcg01_raw::custody::OpenAdmittedManifestDirectory(context.manifestPath,context.manifestSha256);
    char name[DCG01Record::NameBytes]{};DCG01Record::Witness record{};
    if(directory<0){record.failure=DCG01Record::Failure::Create;record.errorNumber=errno;}
    else if(Name(state.identity,"record",name,sizeof(name))) record=DCG01Record::Store(directory,name,seal->record,seal->recordBytes);
    const bool published=order.CompleteRecordPublication(&record);
    bool okay=published;
    unsigned char document[8192]{};DC022Canonical::Writer w(document,sizeof(document));
    okay=okay && w.BeginObject() && w.Key("files") && w.BeginArray() && FileWitness(w,name,record);
    if(okay)
    {
        okay=Name(state.identity,"certificate",name,sizeof(name));
        if(okay){const auto stored=DCG01Record::Store(directory,name,seal->certificate,seal->certificateBytes);
            okay=stored.failure==DCG01Record::Failure::None && FileWitness(w,name,stored);}
    }
    DCG01Terminal::DisconnectSnapshot notice{};
    if(okay && order.CopyDisconnect(&notice))
    {
        okay=Name(state.identity,"notice",name,sizeof(name));
        if(okay){const auto stored=DCG01Record::Store(directory,name,notice.bytes,notice.length);
            okay=stored.failure==DCG01Record::Failure::None && FileWitness(w,name,stored);}
    }
    size_t length=0;uint64_t count=0;
    if(okay) okay=order.CopyTrace(trace.get(),DCG01Events::Stream::MaxBytes,&length,&count) && count &&
        Name(state.identity,"trace",name,sizeof(name));
    if(okay)
    {
        const auto stored=DCG01Record::Store<DCG01Record::System,DCG01Record::MaxTraceBytes>(directory,name,trace.get(),length,
            readback.get(),DCG01Events::Stream::MaxBytes);
        okay=stored.failure==DCG01Record::Failure::None && FileWitness(w,name,stored);
    }
    DCG01Terminal::PublicationSnapshot publication{};
    okay=okay && order.CopyPublication(&publication) && publication.published && w.EndArray() &&
        w.Key("incarnation_id") && w.Hex(state.identity.memberIncarnations[0],16) &&
        w.Key("local_member_id") && w.UInt(1) && w.Key("publication_transition_seq") && w.UInt(publication.transition) &&
        w.Key("run_id") && w.Hex(state.identity.run,16) && w.Key("schema") && w.String("dcg01-terminal-file-witness") &&
        w.Key("version") && w.UInt(1) && w.EndObject() && w.Finish() && Name(state.identity,"witness",name,sizeof(name));
    if(okay) okay=DCG01Record::Store(directory,name,w.Data(),w.Size()).failure==DCG01Record::Failure::None;
    if(directory>=0 && close(directory)!=0) okay=false;
    if(!published || !order.Healthy()) return Result::Failed;
    return okay ? Result::Complete : Result::ExportIncomplete;
}

inline bool PersistFailure(DCG01Terminal::FailureOrder& order,const DistributedAdmissionJournalContext& context)
{
    DCG01Terminal::FailureSnapshot state{};
    if(!order.Copy(&state) || !state.failed) return true;
    if(!Matches(state.identity,context)) return false;
    const int directory=dcg01_raw::custody::OpenAdmittedManifestDirectory(context.manifestPath,context.manifestSha256);
    if(directory<0) return false;
    unsigned char document[4096]{};DC022Canonical::Writer w(document,sizeof(document));
    bool okay=w.BeginObject() && w.Key("abort_order") && w.UInt(state.abortOrder) && w.Key("code") && w.UInt(state.code) &&
        w.Key("failure_events_recorded") && w.Boolean(state.failureEventsRecorded) && w.Key("failure_order") && w.UInt(state.failureOrder) &&
        w.Key("incarnation_id") && w.Hex(state.identity.memberIncarnations[state.identity.localNode-1],16) &&
        w.Key("local_member_id") && w.UInt(state.identity.localNode) && w.Key("origin") && w.UInt(static_cast<unsigned>(state.origin)) &&
        w.Key("reason_overflow") && w.Boolean(state.reasonOverflow) && w.Key("run_id") && w.Hex(state.identity.run,16) &&
        w.Key("schema") && w.String("dcg01-terminal-failure") && w.Key("source_b64") &&
        w.Base64(state.sourceEvidence,state.sourceEvidenceLength) && w.Key("source_sha256") && w.Hex(state.sourceEvidenceDigest,32) &&
        w.Key("version") && w.UInt(1) && w.EndObject() && w.Finish();
    char name[DCG01Record::NameBytes]{};
    okay=okay && Name(state.identity,"failure",name,sizeof(name));
    if(okay) okay=DCG01Record::Store(directory,name,w.Data(),w.Size()).failure==DCG01Record::Failure::None;
    if(state.identity.localNode==1)
    {
        std::unique_ptr<unsigned char[]> trace(new(std::nothrow) unsigned char[DCG01Events::Stream::MaxBytes]);
        std::unique_ptr<unsigned char[]> readback(new(std::nothrow) unsigned char[DCG01Events::Stream::MaxBytes]);
        size_t length=0;uint64_t count=0;
        bool captured=trace && readback && order.CopyTrace(trace.get(),DCG01Events::Stream::MaxBytes,&length,&count) && count &&
            Name(state.identity,"failure-trace",name,sizeof(name));
        if(captured) captured=DCG01Record::Store<DCG01Record::System,DCG01Record::MaxTraceBytes>(directory,name,trace.get(),length,
            readback.get(),DCG01Events::Stream::MaxBytes).failure==DCG01Record::Failure::None;
        okay=okay && captured;
    }
    if(close(directory)!=0) okay=false;
    return okay;
}
}
#endif

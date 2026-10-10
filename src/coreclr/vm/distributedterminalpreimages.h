// Bounded R3 JSON/domain preimage construction over the selected canonical writer.
// This serializes caller-supplied snapshots; it does not authenticate runtime facts.
#ifndef DCG01_NATIVE_COMMIT_PREIMAGES_H
#define DCG01_NATIVE_COMMIT_PREIMAGES_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "distributedcanonicalwriter.h"

namespace DCG01Preimage
{
static const size_t kMaxBytes = 16384;
static const size_t kMaxObjects = 64;
static const size_t kMaxArtifacts = 8; // Frozen canonical_contract.py profile cap over custody rows.
static const size_t kMaxArtifactBytes = 16384;
static const size_t kMaxEvents = 2048;

struct Identity
{
    unsigned char runId[16];
    unsigned char buildDigest[32];
    unsigned char runManifestDigest[32];
    unsigned char incarnation[2][16];
};

struct LogicalId { unsigned char bytes[44]; };

struct Prepared
{
    uint64_t terminalEpoch;
    uint64_t lastOperation;
    uint64_t authorityFrontier;
    uint64_t publicationFrontier;
    LogicalId joinedThreadIds[1];
    size_t joinedCount;
    size_t openOperationCount;
    size_t openPublicationCount;
    unsigned char rootInventoryDigest[32];
    uint64_t resultArtifactIds[8];
    size_t resultArtifactCount;
    uint64_t evidenceArtifactId;
    const unsigned char* evidenceBytes;
    size_t evidenceLength;
    unsigned char evidenceDigest[32];
};

struct Participant
{
    uint32_t memberId;
    Prepared prepared;
    uint64_t snapshotId;
    LogicalId objectIds[kMaxObjects];
    size_t objectCount;
};

struct MainReturn
{
    int32_t resultI32;
    uint64_t outputArtifactIds[8];
    size_t outputArtifactCount;
    uint64_t finalOperationFrontier;
    uint64_t finalAuthorityFrontier;
    uint64_t finalPublicationFrontier;
};

enum ArtifactRole { ApplicationOutput = 1, TerminalEvidence = 2 };
struct Artifact
{
    uint64_t artifactId;
    ArtifactRole role;
    const unsigned char* bytes;
    size_t length;
};

struct Prefix
{
    const unsigned char* bytes;
    size_t length;
    uint64_t eventCount;
};

static const unsigned char kCommitDomain[] = "DC022-PARTICIPANT-COMMITMENT\0v1\0";
static const unsigned char kCertificateDomain[] = "DC022-TERMINAL-CERTIFICATE\0v1\0";
static const unsigned char kRecordDomain[] = "DC022-COMPLETE-RECORD\0v1\0";
static const unsigned char kFrontierDomain[] = "DC022-FINAL-FRONTIERS\0v1\0";

// Hashing is injected through the native callers existing SHA-256 seam.
typedef bool (*HashFunction)(const unsigned char*,size_t,unsigned char[32]);
inline bool Hash(HashFunction hash,const unsigned char* p,size_t n,unsigned char out[32])
{ return hash!=nullptr && (n==0 || p!=nullptr) && hash(p,n,out); }
inline bool Eq(const unsigned char* a, const unsigned char* b, size_t n) { return memcmp(a,b,n)==0; }
inline bool Less(const unsigned char* a, const unsigned char* b, size_t n) { return memcmp(a,b,n)<0; }
inline bool Nonzero(const unsigned char* p, size_t n)
{ unsigned char v=0;for(size_t i=0;i<n;++i)v|=p[i];return v!=0; }
inline bool U64Positive(uint64_t v) { return v != 0; }

inline bool ValidIdentity(const Identity& x)
{ return !Eq(x.incarnation[0],x.incarnation[1],16); }

inline bool ValidLogical(const Identity& x, const LogicalId& id, uint32_t creator)
{
    if (!Eq(id.bytes,x.runId,16)) return false;
    uint32_t member=static_cast<uint32_t>(id.bytes[16]) |
        (static_cast<uint32_t>(id.bytes[17])<<8) | (static_cast<uint32_t>(id.bytes[18])<<16) |
        (static_cast<uint32_t>(id.bytes[19])<<24);
    if ((member!=1 && member!=2) || (creator!=0 && member!=creator) ||
        !Eq(id.bytes+20,x.incarnation[member-1],16)) return false;
    uint64_t count=0;for(size_t i=0;i<8;++i)count|=static_cast<uint64_t>(id.bytes[36+i])<<(8*i);
    return count>=1 && count<=64;
}

inline bool ValidParticipant(const Identity& x, const Participant& p,HashFunction hash)
{
    const Prepared& q=p.prepared;
    if (!ValidIdentity(x) || (p.memberId!=1 && p.memberId!=2) || !U64Positive(q.terminalEpoch) ||
        q.joinedCount>1 || q.openOperationCount!=0 || q.openPublicationCount!=0 ||
        q.resultArtifactCount>8 || !U64Positive(q.evidenceArtifactId) || q.evidenceLength>kMaxArtifactBytes ||
        (q.evidenceLength!=0 && q.evidenceBytes==nullptr) || p.objectCount>kMaxObjects ||
        !U64Positive(p.snapshotId)) return false;
    unsigned char evidenceDigest[32];if(!Hash(hash,q.evidenceBytes,q.evidenceLength,evidenceDigest))return false;
    if(!Eq(evidenceDigest,q.evidenceDigest,32))return false;
    for(size_t i=0;i<q.joinedCount;++i)
        if(!ValidLogical(x,q.joinedThreadIds[i],1))return false;
    for(size_t i=1;i<q.joinedCount;++i)
        if(!Less(q.joinedThreadIds[i-1].bytes,q.joinedThreadIds[i].bytes,44))return false;
    for(size_t i=0;i<q.resultArtifactCount;++i)
    { if(!U64Positive(q.resultArtifactIds[i]))return false;
      if(i && q.resultArtifactIds[i-1]>=q.resultArtifactIds[i])return false; }
    for(size_t i=0;i<p.objectCount;++i)
    { if(!ValidLogical(x,p.objectIds[i],0))return false;
      for(size_t j=0;j<i;++j)if(Eq(p.objectIds[j].bytes,p.objectIds[i].bytes,44))return false; }
    return true;
}

#define DCG01_TRY(call) do { if (!(call)) return false; } while (0)
inline bool PutIdentity(DC022Canonical::Writer& w, const Identity& x)
{
    DCG01_TRY(w.BeginObject());
    DCG01_TRY(w.Key("build_manifest_sha256")); DCG01_TRY(w.Hex(x.buildDigest,32));
    DCG01_TRY(w.Key("members")); DCG01_TRY(w.BeginArray());
    for(uint32_t m=1;m<=2;++m)
    { DCG01_TRY(w.BeginObject()); DCG01_TRY(w.Key("incarnation_id")); DCG01_TRY(w.Hex(x.incarnation[m-1],16));
      DCG01_TRY(w.Key("member_id")); DCG01_TRY(w.UInt(m)); DCG01_TRY(w.Key("role"));
      const char* role=m==1?"coordinator":"worker";DCG01_TRY(w.String(role,strlen(role))); DCG01_TRY(w.EndObject()); }
    DCG01_TRY(w.EndArray()); DCG01_TRY(w.Key("run_id")); DCG01_TRY(w.Hex(x.runId,16));
    DCG01_TRY(w.Key("run_manifest_sha256")); DCG01_TRY(w.Hex(x.runManifestDigest,32));
    DCG01_TRY(w.Key("runtime_profile")); DCG01_TRY(w.String("dc013-instance-thread-linux-x64-v1"));
    DCG01_TRY(w.Key("trace_profile")); DCG01_TRY(w.String("thread-object-v1"));
    return w.EndObject();
}

inline bool PutParticipantIdentity(DC022Canonical::Writer& w,const Identity& x,uint32_t memberId)
{
    DCG01_TRY(w.BeginObject());
    DCG01_TRY(w.Key("build_manifest_sha256"));DCG01_TRY(w.Hex(x.buildDigest,32));
    DCG01_TRY(w.Key("incarnation_id"));DCG01_TRY(w.Hex(x.incarnation[memberId-1],16));
    DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(memberId));
    DCG01_TRY(w.Key("members"));DCG01_TRY(w.BeginArray());
    for(uint32_t m=1;m<=2;++m)
    { DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("incarnation_id"));DCG01_TRY(w.Hex(x.incarnation[m-1],16));
      DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(m));DCG01_TRY(w.Key("role"));
      const char* role=m==1?"coordinator":"worker";DCG01_TRY(w.String(role,strlen(role)));DCG01_TRY(w.EndObject()); }
    DCG01_TRY(w.EndArray());DCG01_TRY(w.Key("role"));
    const char* role=memberId==1?"coordinator":"worker";DCG01_TRY(w.String(role,strlen(role)));
    DCG01_TRY(w.Key("run_id"));DCG01_TRY(w.Hex(x.runId,16));
    DCG01_TRY(w.Key("run_manifest_sha256"));DCG01_TRY(w.Hex(x.runManifestDigest,32));
    DCG01_TRY(w.Key("runtime_profile"));DCG01_TRY(w.String("dc013-instance-thread-linux-x64-v1"));
    DCG01_TRY(w.Key("trace_profile"));DCG01_TRY(w.String("thread-object-v1"));
    return w.EndObject();
}

inline bool PutRootInventory(DC022Canonical::Writer& w, const Identity& x, const Participant& p)
{
    LogicalId sorted[kMaxObjects];
    for(size_t i=0;i<p.objectCount;++i)sorted[i]=p.objectIds[i];
    for(size_t i=1;i<p.objectCount;++i){LogicalId v=sorted[i];size_t j=i;
        while(j>0 && Less(v.bytes,sorted[j-1].bytes,44)){sorted[j]=sorted[j-1];--j;}sorted[j]=v;}
    DCG01_TRY(w.BeginObject()); DCG01_TRY(w.Key("incarnation_id")); DCG01_TRY(w.Hex(x.incarnation[p.memberId-1],16));
    DCG01_TRY(w.Key("member_id")); DCG01_TRY(w.UInt(p.memberId)); DCG01_TRY(w.Key("object_ids")); DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<p.objectCount;++i)DCG01_TRY(w.Hex(sorted[i].bytes,44));
    DCG01_TRY(w.EndArray()); DCG01_TRY(w.Key("run_id")); DCG01_TRY(w.Hex(x.runId,16));
    DCG01_TRY(w.Key("schema")); DCG01_TRY(w.String("dc022-root-inventory"));
    DCG01_TRY(w.Key("snapshot_id")); DCG01_TRY(w.UInt(p.snapshotId));
    DCG01_TRY(w.Key("terminal_epoch")); DCG01_TRY(w.UInt(p.prepared.terminalEpoch));
    DCG01_TRY(w.Key("version")); DCG01_TRY(w.UInt(2)); return w.EndObject();
}

inline bool RootInventory(const Identity& x, const Participant& p,HashFunction hash,unsigned char* out, size_t cap,
                          size_t* written, unsigned char digest[32])
{
    if(written) *written=0;
    if(!written||!digest||!out||cap==0||!ValidParticipant(x,p,hash))return false;
    unsigned char tmp[kMaxBytes]; DC022Canonical::Writer w(tmp,sizeof(tmp));
    if(!PutRootInventory(w,x,p)||!w.Finish())return false;
    size_t n=w.Size();unsigned char localDigest[32];
    if(n>cap||!Hash(hash,tmp,n,localDigest))return false;
    memcpy(out,tmp,n);memcpy(digest,localDigest,32);*written=n;return true;
}

inline bool FrontierDigest(const Identity& x,const Participant& p,HashFunction hash,unsigned char out[32])
{
    // This helper is directly callable; guard its array index and write target here.
    // Full participant admission remains the caller's ValidParticipant/ValidBundle gate.
    if(!out||!hash||!ValidIdentity(x)||(p.memberId!=1&&p.memberId!=2)||!U64Positive(p.prepared.terminalEpoch))return false;
    unsigned char tmp[1024]; DC022Canonical::Writer w(tmp,sizeof(tmp),kFrontierDomain,sizeof(kFrontierDomain)-1);
    DCG01_TRY(w.BeginObject()); DCG01_TRY(w.Key("authority_frontier"));DCG01_TRY(w.UInt(p.prepared.authorityFrontier));
    DCG01_TRY(w.Key("incarnation_id"));DCG01_TRY(w.Hex(x.incarnation[p.memberId-1],16));
    DCG01_TRY(w.Key("last_member_operation_sequence"));DCG01_TRY(w.UInt(p.prepared.lastOperation));
    DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(p.memberId));
    DCG01_TRY(w.Key("publication_frontier"));DCG01_TRY(w.UInt(p.prepared.publicationFrontier));
    DCG01_TRY(w.Key("run_id"));DCG01_TRY(w.Hex(x.runId,16));
    DCG01_TRY(w.Key("schema"));DCG01_TRY(w.String("dc022-final-frontiers"));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(p.prepared.terminalEpoch));
    DCG01_TRY(w.Key("version"));DCG01_TRY(w.UInt(1));DCG01_TRY(w.EndObject());DCG01_TRY(w.Finish());
    unsigned char localDigest[32];if(!Hash(hash,tmp,w.Size(),localDigest))return false;
    memcpy(out,localDigest,32);return true;
}

inline bool PutCommitment(const Identity& x,const Participant& p,HashFunction hash,const unsigned char frontier[32],
                          const Participant& inventoryOwner,DC022Canonical::Writer& w)
{
    const Prepared& q=p.prepared;
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("identity"));DCG01_TRY(PutParticipantIdentity(w,x,p.memberId));
    DCG01_TRY(w.Key("schema"));DCG01_TRY(w.String("dc022-participant-terminal-commitment"));
    DCG01_TRY(w.Key("terminal"));DCG01_TRY(w.BeginObject());
    DCG01_TRY(w.Key("authority_frontier"));DCG01_TRY(w.UInt(q.authorityFrontier));
    DCG01_TRY(w.Key("evidence_artifact_id"));DCG01_TRY(w.UInt(q.evidenceArtifactId));
    DCG01_TRY(w.Key("evidence_bytes"));DCG01_TRY(w.UInt(q.evidenceLength));
    unsigned char evidenceDigest[32];DCG01_TRY(Hash(hash,q.evidenceBytes,q.evidenceLength,evidenceDigest));
    DCG01_TRY(w.Key("evidence_sha256"));DCG01_TRY(w.Hex(evidenceDigest,32));
    DCG01_TRY(w.Key("final_frontiers_digest"));DCG01_TRY(w.Hex(frontier,32));
    DCG01_TRY(w.Key("joined_thread_ids"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<q.joinedCount;++i) DCG01_TRY(w.Hex(q.joinedThreadIds[i].bytes,44));
    DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("last_member_operation_sequence"));DCG01_TRY(w.UInt(q.lastOperation));
    DCG01_TRY(w.Key("open_operation_sequences"));DCG01_TRY(w.BeginArray());DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("open_publication_ids"));DCG01_TRY(w.BeginArray());DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("publication_frontier"));DCG01_TRY(w.UInt(q.publicationFrontier));
    DCG01_TRY(w.Key("result_artifact_ids"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<q.resultArtifactCount;++i) DCG01_TRY(w.UInt(q.resultArtifactIds[i]));
    DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("root_inventory"));DCG01_TRY(PutRootInventory(w,x,inventoryOwner));
    DCG01_TRY(w.Key("root_inventory_sha256"));DCG01_TRY(w.Hex(q.rootInventoryDigest,32));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(q.terminalEpoch));
    DCG01_TRY(w.EndObject());DCG01_TRY(w.Key("version"));DCG01_TRY(w.UInt(1));return w.EndObject();
}

inline bool EncodeParticipant(const Identity& x,const Participant& p,HashFunction hash,unsigned char* out,size_t cap,
                              size_t* written,unsigned char digest[32])
{
    if(written) *written=0;
    if(!written||!digest||!out||cap==0||!ValidParticipant(x,p,hash))return false;
    unsigned char root[kMaxBytes],rootDigest[32],frontier[32];size_t rootSize=0;
    if(!RootInventory(x,p,hash,root,sizeof(root),&rootSize,rootDigest)||!Eq(rootDigest,p.prepared.rootInventoryDigest,32))return false;
    if(!FrontierDigest(x,p,hash,frontier))return false;
    unsigned char tmp[kMaxBytes];DC022Canonical::Writer w(tmp,sizeof(tmp),kCommitDomain,sizeof(kCommitDomain)-1);
    if(!PutCommitment(x,p,hash,frontier,p,w)||!w.Finish())return false;
    size_t n=w.Size();unsigned char localDigest[32];
    if(n>cap||!Hash(hash,tmp,n,localDigest))return false;
    memcpy(out,tmp,n);memcpy(digest,localDigest,32);*written=n;return true;
}

inline bool ValidMain(const MainReturn& m)
{
    if(m.outputArtifactCount>8)return false;
    for(size_t i=0;i<m.outputArtifactCount;++i)
        if(!U64Positive(m.outputArtifactIds[i])||(i&&m.outputArtifactIds[i-1]>=m.outputArtifactIds[i]))return false;
    return true;
}
inline bool PutMain(DC022Canonical::Writer& w,const MainReturn& m)
{
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("final_authority_frontier"));DCG01_TRY(w.UInt(m.finalAuthorityFrontier));
    DCG01_TRY(w.Key("final_operation_frontier"));DCG01_TRY(w.UInt(m.finalOperationFrontier));
    DCG01_TRY(w.Key("final_publication_frontier"));DCG01_TRY(w.UInt(m.finalPublicationFrontier));
    DCG01_TRY(w.Key("outcome"));DCG01_TRY(w.String("returned"));
    DCG01_TRY(w.Key("output_artifact_ids"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<m.outputArtifactCount;++i)DCG01_TRY(w.UInt(m.outputArtifactIds[i]));
    DCG01_TRY(w.EndArray());DCG01_TRY(w.Key("result_i32"));DCG01_TRY(w.Int(m.resultI32));return w.EndObject();
}

inline bool ValidArtifacts(const Artifact* a,size_t n)
{
    if(n>kMaxArtifacts||(n&&a==nullptr))return false;
    for(size_t i=0;i<n;++i)
    { if(!U64Positive(a[i].artifactId)||a[i].length>kMaxArtifactBytes||(a[i].length&&a[i].bytes==nullptr)||
          (a[i].role!=ApplicationOutput&&a[i].role!=TerminalEvidence))return false;
      for(size_t j=0;j<i;++j)if(a[j].artifactId==a[i].artifactId)return false; }
    return true;
}
inline void ManifestOrder(const Artifact* a,size_t n,size_t order[kMaxArtifacts])
{ for(size_t i=0;i<n;++i)order[i]=i;for(size_t i=1;i<n;++i){size_t v=order[i],j=i;while(j&&a[order[j-1]].artifactId>a[v].artifactId){order[j]=order[j-1];--j;}order[j]=v;} }
inline size_t CountRole(const Artifact* a,size_t n,ArtifactRole role)
{ size_t k=0;for(size_t i=0;i<n;++i)if(a[i].role==role)++k;return k; }
inline bool PutManifest(DC022Canonical::Writer& w,const Artifact* a,size_t n,ArtifactRole role,HashFunction hash)
{
    size_t order[kMaxArtifacts];ManifestOrder(a,n,order);DCG01_TRY(w.BeginArray());
    for(size_t j=0;j<n;++j){const Artifact& v=a[order[j]];if(v.role!=role)continue;
        unsigned char digest[32];DCG01_TRY(Hash(hash,v.bytes,v.length,digest));DCG01_TRY(w.BeginObject());
        DCG01_TRY(w.Key("artifact_id"));DCG01_TRY(w.UInt(v.artifactId));DCG01_TRY(w.Key("content_bytes"));DCG01_TRY(w.UInt(v.length));
        const char* roleName=role==ApplicationOutput?"application_output":"terminal_evidence";
        DCG01_TRY(w.Key("role"));DCG01_TRY(w.String(roleName,strlen(roleName)));
        DCG01_TRY(w.Key("sha256"));DCG01_TRY(w.Hex(digest,32));DCG01_TRY(w.EndObject());}
    return w.EndArray();
}

inline bool OutputEvidenceCustodyDigest(const Identity& x,const Participant& p,const Artifact* artifacts,
                                       size_t count,HashFunction hash,unsigned char digest[32])
{
    if(!digest || !ValidParticipant(x,p,hash) || !ValidArtifacts(artifacts,count))return false;
    const Prepared& q=p.prepared;
    for(size_t i=0;i<q.resultArtifactCount;++i)if(q.resultArtifactIds[i]==q.evidenceArtifactId)return false;
    size_t order[kMaxArtifacts];ManifestOrder(artifacts,count,order);
    size_t found=0;unsigned char tmp[kMaxBytes];
    static const unsigned char domain[]="DC022-OUTPUT-EVIDENCE-CUSTODY\0v1\0";
    DC022Canonical::Writer w(tmp,sizeof(tmp),domain,sizeof(domain)-1);
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("artifacts"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<count;++i)
    {
        const Artifact& a=artifacts[order[i]];const bool evidence=a.artifactId==q.evidenceArtifactId;
        bool output=false;for(size_t j=0;j<q.resultArtifactCount;++j)if(a.artifactId==q.resultArtifactIds[j])output=true;
        if(!evidence&&!output)continue;
        if(a.role!=(evidence?TerminalEvidence:ApplicationOutput))return false;
        unsigned char contentDigest[32];DCG01_TRY(Hash(hash,a.bytes,a.length,contentDigest));
        if(evidence&&(a.length!=q.evidenceLength||!Eq(contentDigest,q.evidenceDigest,32)))return false;
        ++found;DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("artifact_id"));DCG01_TRY(w.UInt(a.artifactId));
        DCG01_TRY(w.Key("content_bytes"));DCG01_TRY(w.UInt(a.length));DCG01_TRY(w.Key("role"));
        const char* role=evidence?"terminal_evidence":"application_output";DCG01_TRY(w.String(role,strlen(role)));
        DCG01_TRY(w.Key("sha256"));DCG01_TRY(w.Hex(contentDigest,32));DCG01_TRY(w.EndObject());
    }
    if(found!=q.resultArtifactCount+1)return false;
    DCG01_TRY(w.EndArray());DCG01_TRY(w.Key("incarnation_id"));DCG01_TRY(w.Hex(x.incarnation[p.memberId-1],16));
    DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(p.memberId));DCG01_TRY(w.Key("run_id"));DCG01_TRY(w.Hex(x.runId,16));
    DCG01_TRY(w.Key("schema"));DCG01_TRY(w.String("dc022-output-evidence-custody"));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(q.terminalEpoch));DCG01_TRY(w.Key("version"));DCG01_TRY(w.UInt(1));
    DCG01_TRY(w.EndObject());DCG01_TRY(w.Finish());unsigned char computed[32];DCG01_TRY(Hash(hash,tmp,w.Size(),computed));
    memcpy(digest,computed,32);return true;
}

inline bool ValidBundle(const Identity& x,uint64_t cutId,const MainReturn& m,const Participant p[2],HashFunction hash,
                        const Artifact* artifacts,size_t artifactCount,const Prefix& prefix)
{
    if(p==nullptr||!ValidIdentity(x)||!U64Positive(cutId)||!ValidMain(m)||!ValidArtifacts(artifacts,artifactCount)||
       CountRole(artifacts,artifactCount,TerminalEvidence)!=2||prefix.bytes==nullptr||prefix.length==0||
       prefix.length>1024*1024||prefix.eventCount>kMaxEvents)return false;
    if(p[0].memberId!=1||p[1].memberId!=2||!ValidParticipant(x,p[0],hash)||!ValidParticipant(x,p[1],hash)||
       p[0].prepared.terminalEpoch!=p[1].prepared.terminalEpoch)return false;
    size_t expectedN=p[0].prepared.resultArtifactCount+p[1].prepared.resultArtifactCount;
    if(expectedN>8)return false;
    uint64_t expected[8];size_t at=0;
    for(size_t i=0;i<2;++i)for(size_t j=0;j<p[i].prepared.resultArtifactCount;++j)
        expected[at++]=p[i].prepared.resultArtifactIds[j];
    for(size_t i=1;i<expectedN;++i){uint64_t v=expected[i];size_t j=i;while(j&&expected[j-1]>v){expected[j]=expected[j-1];--j;}expected[j]=v;}
    if(expectedN!=m.outputArtifactCount||CountRole(artifacts,artifactCount,ApplicationOutput)!=expectedN||
       p[0].prepared.evidenceArtifactId==p[1].prepared.evidenceArtifactId)return false;
    for(size_t i=0;i<expectedN;++i)if(expected[i]!=m.outputArtifactIds[i]||(i&&expected[i-1]==expected[i]))return false;
    for(size_t mid=0;mid<2;++mid)
    { size_t found=0;for(size_t j=0;j<artifactCount;++j)if(artifacts[j].role==TerminalEvidence&&artifacts[j].artifactId==p[mid].prepared.evidenceArtifactId){
          unsigned char d[32];if(!Hash(hash,artifacts[j].bytes,artifacts[j].length,d))return false;
          if(artifacts[j].length!=p[mid].prepared.evidenceLength||!Eq(d,p[mid].prepared.evidenceDigest,32)||
             (artifacts[j].length&&memcmp(artifacts[j].bytes,p[mid].prepared.evidenceBytes,artifacts[j].length)!=0))return false;
          found++;}
      if(found!=1)return false; }
    for(size_t j=0;j<artifactCount;++j)if(artifacts[j].role==ApplicationOutput){bool found=false;
        for(size_t mId=0;mId<2;++mId)for(size_t k=0;k<p[mId].prepared.resultArtifactCount;++k)
            if(artifacts[j].artifactId==p[mId].prepared.resultArtifactIds[k])found=true;
        if(!found)return false;}
    return true;
}

inline bool PutCut(DC022Canonical::Writer& w,const Identity& x,const Participant& p,const unsigned char commitDigest[32])
{
    const Prepared& q=p.prepared;
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("authority_frontier"));DCG01_TRY(w.UInt(q.authorityFrontier));
    DCG01_TRY(w.Key("commitment_digest"));DCG01_TRY(w.Hex(commitDigest,32));
    DCG01_TRY(w.Key("incarnation_id"));DCG01_TRY(w.Hex(x.incarnation[p.memberId-1],16));
    DCG01_TRY(w.Key("joined_thread_ids"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<q.joinedCount;++i) DCG01_TRY(w.Hex(q.joinedThreadIds[i].bytes,44));
    DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(p.memberId));
    DCG01_TRY(w.Key("member_operation_sequence"));DCG01_TRY(w.UInt(q.lastOperation));
    DCG01_TRY(w.Key("publication_frontier"));DCG01_TRY(w.UInt(q.publicationFrontier));
    DCG01_TRY(w.Key("root_inventory_sha256"));DCG01_TRY(w.Hex(q.rootInventoryDigest,32));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(q.terminalEpoch));return w.EndObject();
}

inline bool PutPrefix(DC022Canonical::Writer& w,const Prefix& p,HashFunction hash)
{
    unsigned char digest[32];DCG01_TRY(Hash(hash,p.bytes,p.length,digest));
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("byte_count"));DCG01_TRY(w.UInt(p.length));
    DCG01_TRY(w.Key("event_count"));DCG01_TRY(w.UInt(p.eventCount));
    DCG01_TRY(w.Key("sha256"));DCG01_TRY(w.Hex(digest,32));return w.EndObject();
}

inline bool BuildCertificate(const Identity& x,uint64_t cutId,const MainReturn& main,HashFunction hash,
                             const Participant p[2],const Artifact* artifacts,size_t artifactCount,
                             const Prefix& prefix,unsigned char* out,size_t cap,size_t* written,
                             unsigned char digest[32])
{
    if(written)*written=0;
    if(!written||!digest||!out||cap==0||!ValidBundle(x,cutId,main,p,hash,artifacts,artifactCount,prefix))return false;
    unsigned char frames[2][kMaxBytes],frameDigests[2][32];size_t frameSizes[2]={0,0};
    for(size_t i=0;i<2;++i)
        if(!EncodeParticipant(x,p[i],hash,frames[i],sizeof(frames[i]),&frameSizes[i],frameDigests[i]))return false;
    unsigned char tmp[kMaxBytes];
    DC022Canonical::Writer w(tmp,sizeof(tmp),kCertificateDomain,sizeof(kCertificateDomain)-1);
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("captured_evidence_prefix"));DCG01_TRY(PutPrefix(w,prefix,hash));
    DCG01_TRY(w.Key("cut_id"));DCG01_TRY(w.UInt(cutId));DCG01_TRY(w.Key("identity"));DCG01_TRY(PutIdentity(w,x));
    DCG01_TRY(w.Key("main_return"));DCG01_TRY(PutMain(w,main));
    DCG01_TRY(w.Key("participant_commitments"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<2;++i){DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("commitment_bytes"));DCG01_TRY(w.UInt(frameSizes[i]));
        DCG01_TRY(w.Key("commitment_sha256"));DCG01_TRY(w.Hex(frameDigests[i],32));
        DCG01_TRY(w.Key("member_id"));DCG01_TRY(w.UInt(p[i].memberId));DCG01_TRY(w.EndObject());}
    DCG01_TRY(w.EndArray());DCG01_TRY(w.Key("participant_cuts"));DCG01_TRY(w.BeginArray());
    for(size_t i=0;i<2;++i) DCG01_TRY(PutCut(w,x,p[i],frameDigests[i]));
    DCG01_TRY(w.EndArray());
    DCG01_TRY(w.Key("required_outputs"));DCG01_TRY(PutManifest(w,artifacts,artifactCount,ApplicationOutput,hash));
    DCG01_TRY(w.Key("required_terminal_evidence"));DCG01_TRY(PutManifest(w,artifacts,artifactCount,TerminalEvidence,hash));
    DCG01_TRY(w.Key("schema"));DCG01_TRY(w.String("dc022-terminal-certificate"));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(p[0].prepared.terminalEpoch));
    DCG01_TRY(w.Key("version"));DCG01_TRY(w.UInt(1));DCG01_TRY(w.EndObject());DCG01_TRY(w.Finish());
    size_t n=w.Size();unsigned char localDigest[32];
    if(n>cap||!Hash(hash,tmp,n,localDigest))return false;
    memcpy(out,tmp,n);memcpy(digest,localDigest,32);*written=n;return true;
}

inline bool BuildCompleteRecord(const Identity& x,uint64_t cutId,const MainReturn& main,HashFunction hash,
                                const Participant p[2],const Artifact* artifacts,size_t artifactCount,
                                const Prefix& prefix,const unsigned char* certificate,size_t certificateSize,
                                const unsigned char* sealEvent,size_t sealEventSize,
                                unsigned char* out,size_t cap,size_t* written,unsigned char digest[32])
{
    if(written)*written=0;
    if(!written||!digest||!out||cap==0||!certificate||certificateSize==0||certificateSize>kMaxBytes||
       !sealEvent||sealEventSize==0||sealEventSize>32768||!ValidBundle(x,cutId,main,p,hash,artifacts,artifactCount,prefix))return false;
    unsigned char expected[kMaxBytes],expectedDigest[32];size_t expectedSize=0;
    if(!BuildCertificate(x,cutId,main,hash,p,artifacts,artifactCount,prefix,expected,sizeof(expected),
                         &expectedSize,expectedDigest)||expectedSize!=certificateSize||
       memcmp(expected,certificate,certificateSize)!=0)return false;
    unsigned char certificateDigest[32],sealDigest[32];if(!Hash(hash,certificate,certificateSize,certificateDigest))return false;
    if(!Eq(certificateDigest,expectedDigest,32))return false;
    if(!Hash(hash,sealEvent,sealEventSize,sealDigest))return false;
    unsigned char tmp[kMaxBytes];
    DC022Canonical::Writer w(tmp,sizeof(tmp),kRecordDomain,sizeof(kRecordDomain)-1);
    DCG01_TRY(w.BeginObject());DCG01_TRY(w.Key("captured_evidence_prefix"));DCG01_TRY(PutPrefix(w,prefix,hash));
    DCG01_TRY(w.Key("cut_id"));DCG01_TRY(w.UInt(cutId));DCG01_TRY(w.Key("identity"));DCG01_TRY(PutIdentity(w,x));
    DCG01_TRY(w.Key("main_return"));DCG01_TRY(PutMain(w,main));
    DCG01_TRY(w.Key("output_availability"));DCG01_TRY(w.BeginObject());
    DCG01_TRY(w.Key("artifacts"));DCG01_TRY(PutManifest(w,artifacts,artifactCount,ApplicationOutput,hash));
    DCG01_TRY(w.Key("location"));DCG01_TRY(w.String("coordinator-custody-before-seal"));DCG01_TRY(w.EndObject());
    DCG01_TRY(w.Key("schema"));DCG01_TRY(w.String("dc022-complete-record"));
    DCG01_TRY(w.Key("sealed_event_sha256"));DCG01_TRY(w.Hex(sealDigest,32));
    DCG01_TRY(w.Key("terminal_certificate_sha256"));DCG01_TRY(w.Hex(certificateDigest,32));
    DCG01_TRY(w.Key("terminal_epoch"));DCG01_TRY(w.UInt(p[0].prepared.terminalEpoch));
    DCG01_TRY(w.Key("terminal_evidence"));DCG01_TRY(PutManifest(w,artifacts,artifactCount,TerminalEvidence,hash));
    DCG01_TRY(w.Key("version"));DCG01_TRY(w.UInt(1));DCG01_TRY(w.EndObject());DCG01_TRY(w.Finish());
    size_t n=w.Size();unsigned char localDigest[32];
    if(n>cap||!Hash(hash,tmp,n,localDigest))return false;
    memcpy(out,tmp,n);memcpy(digest,localDigest,32);*written=n;return true;
}

#undef DCG01_TRY
}
#endif

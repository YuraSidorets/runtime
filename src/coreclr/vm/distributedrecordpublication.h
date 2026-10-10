// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#ifndef DISTRIBUTED_RECORD_PUBLICATION_H
#define DISTRIBUTED_RECORD_PUBLICATION_H
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace DCG01Record
{
constexpr size_t MaxBytes=16384,NameBytes=128;
constexpr size_t MaxTraceBytes=1024*1024;
enum class Failure { None, Create, Write, Flush, AtomicPublish, Readback, Unknown };
struct Witness
{
    Failure failure=Failure::Unknown;
    int errorNumber=0;
    bool fileFlushed=false,renamed=false,directoryFlushed=false,readbackMatched=false;
    uint64_t directoryDevice=0,directoryInode=0,fileDevice=0,fileInode=0;
    size_t written=0,length=0;
    unsigned char digest[32]{},readback[MaxBytes]{};
};

struct System
{
    static int Stat(int fd,struct stat* s){return fstat(fd,s);}
    static int StatName(int fd,const char* name,struct stat* s){return fstatat(fd,name,s,AT_SYMLINK_NOFOLLOW);}
    static int Open(int fd,const char* name,int flags,mode_t mode){return openat(fd,name,flags,mode);}
    static ssize_t Write(int fd,const void* p,size_t n){return write(fd,p,n);}
    static ssize_t Read(int fd,void* p,size_t n){return read(fd,p,n);}
    static int Chmod(int fd,mode_t mode){return fchmod(fd,mode);}
    static int Sync(int fd){return fsync(fd);}
    static int Close(int fd){return close(fd);}
    static int Publish(int fd,const char* pending,const char* name)
    {return static_cast<int>(syscall(SYS_renameat2,fd,pending,fd,name,RENAME_NOREPLACE));}
    static bool Hash(const unsigned char* p,size_t n,unsigned char* out){return SHA256(p,n,out)!=nullptr;}
};

inline bool SameFile(const struct stat& a,const struct stat& b)
{
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_uid==b.st_uid && a.st_mode==b.st_mode &&
        a.st_nlink==b.st_nlink && a.st_size==b.st_size &&
        a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
inline bool ValidName(const char* name)
{
    if (!name) return false;
    const size_t length=strnlen(name,NameBytes);
    if (length<6 || length+sizeof(".pending")>NameBytes || name[0]=='.') return false;
    for(size_t i=0;i<length;++i)
        if (!((name[i]>='a'&&name[i]<='z') || (name[i]>='0'&&name[i]<='9') ||
              name[i]=='.' || name[i]=='-' || name[i]=='_')) return false;
    return true;
}

// Caller supplies an already-admitted owner-private directory descriptor and an
// immutable record snapshot. No runtime lock is acquired here. This witness is
// file evidence only: a healthy serialized terminal decision must still accept it.
// Failed/pending files are preserved; existing names are never overwritten.
template<class IO=System,size_t Bound=MaxBytes>
Witness Store(int directory,const char* name,const unsigned char* bytes,size_t length,
              unsigned char* traceReadback=nullptr,size_t traceCapacity=0)
{
    static_assert(Bound==MaxBytes || Bound==MaxTraceBytes,"Only record and canonical trace bounds are supported");
    Witness out{};out.length=length;
    unsigned char* readback=Bound==MaxBytes?out.readback:traceReadback;
    if (directory<0 || !ValidName(name) || !bytes || !length || length>Bound || !readback ||
        (Bound==MaxTraceBytes && traceCapacity<length) || (Bound==MaxBytes && (traceReadback || traceCapacity)))
    {out.errorNumber=EINVAL;return out;}
    if (!IO::Hash(bytes,length,out.digest)){out.errorNumber=EIO;return out;}
    struct stat dir{};
    if (IO::Stat(directory,&dir)!=0){out.failure=Failure::Create;out.errorNumber=errno;return out;}
    if (!S_ISDIR(dir.st_mode) || dir.st_uid!=geteuid() || (dir.st_mode&0077)!=0)
    {out.failure=Failure::Create;out.errorNumber=EPERM;return out;}
    out.directoryDevice=dir.st_dev;out.directoryInode=dir.st_ino;
    char pending[NameBytes]{};snprintf(pending,sizeof(pending),"%s.pending",name);
    int fd=IO::Open(directory,pending,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
    if(fd<0){out.failure=Failure::Create;out.errorNumber=errno;return out;}
    auto fail=[&](Failure kind,int error)->Witness
    {
        out.failure=kind;out.errorNumber=error?error:EIO;
        if(fd>=0){IO::Close(fd);fd=-1;}
        return out;
    };
    struct stat created{};
    if(IO::Stat(fd,&created)!=0) return fail(Failure::Create,errno);
    if(!S_ISREG(created.st_mode) || created.st_uid!=geteuid() || created.st_nlink!=1 ||
       (created.st_mode&0777)!=0600 || created.st_size!=0) return fail(Failure::Create,EPERM);
    out.fileDevice=created.st_dev;out.fileInode=created.st_ino;
    while(out.written<length)
    {
        const ssize_t n=IO::Write(fd,bytes+out.written,length-out.written);
        if(n<0&&errno==EINTR) continue;
        if(n<=0 || static_cast<size_t>(n)>length-out.written) return fail(Failure::Write,n<0?errno:EIO);
        out.written+=static_cast<size_t>(n);
    }
    if(IO::Chmod(fd,0400)!=0 || IO::Sync(fd)!=0) return fail(Failure::Flush,errno);
    out.fileFlushed=true;
    struct stat staged{};
    if(IO::Stat(fd,&staged)!=0) return fail(Failure::Flush,errno);
    if(staged.st_dev!=created.st_dev || staged.st_ino!=created.st_ino || !S_ISREG(staged.st_mode) ||
       staged.st_uid!=geteuid() || staged.st_nlink!=1 || (staged.st_mode&0777)!=0400 ||
       staged.st_size!=static_cast<off_t>(length)) return fail(Failure::Flush,EPERM);
    const int closed=IO::Close(fd);fd=-1;
    if(closed!=0) return fail(Failure::Flush,errno); // Never retry close on a reused descriptor.
    struct stat named{};
    if(IO::StatName(directory,pending,&named)!=0) return fail(Failure::AtomicPublish,errno);
    if(!SameFile(staged,named)) return fail(Failure::AtomicPublish,EPERM);
    if(IO::Publish(directory,pending,name)!=0) return fail(Failure::AtomicPublish,errno);
    out.renamed=true;
    if(IO::Sync(directory)!=0) return fail(Failure::Flush,errno);
    out.directoryFlushed=true;
    fd=IO::Open(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0);
    if(fd<0) return fail(Failure::Readback,errno);
    struct stat before{};
    if(IO::Stat(fd,&before)!=0) return fail(Failure::Readback,errno);
    // Rename may change ctime; all object/content properties must still match.
    if(before.st_dev!=staged.st_dev || before.st_ino!=staged.st_ino || before.st_uid!=staged.st_uid ||
       before.st_mode!=staged.st_mode || before.st_nlink!=1 || before.st_size!=static_cast<off_t>(length) ||
       before.st_mtim.tv_sec!=staged.st_mtim.tv_sec || before.st_mtim.tv_nsec!=staged.st_mtim.tv_nsec)
        return fail(Failure::Readback,EPERM);
    size_t offset=0;
    while(offset<length)
    {
        const ssize_t n=IO::Read(fd,readback+offset,length-offset);
        if(n<0&&errno==EINTR) continue;
        if(n<=0 || static_cast<size_t>(n)>length-offset) return fail(Failure::Readback,n<0?errno:EIO);
        offset+=static_cast<size_t>(n);
    }
    unsigned char extra=0;ssize_t tail;
    do {tail=IO::Read(fd,&extra,1);} while(tail<0&&errno==EINTR);
    if(tail!=0) return fail(Failure::Readback,tail<0?errno:EIO);
    struct stat after{};
    if(IO::Stat(fd,&after)!=0 || IO::StatName(directory,name,&named)!=0) return fail(Failure::Readback,errno);
    if(!SameFile(before,after) || !SameFile(after,named) || memcmp(readback,bytes,length)) return fail(Failure::Readback,EIO);
    unsigned char digest[32]{};
    if(!IO::Hash(readback,length,digest) || memcmp(digest,out.digest,32)) return fail(Failure::Readback,EIO);
    const int readClosed=IO::Close(fd);fd=-1;
    if(readClosed!=0) return fail(Failure::Readback,errno);
    out.readbackMatched=true;out.failure=Failure::None;return out;
}
}
#endif

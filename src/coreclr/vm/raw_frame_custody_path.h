#ifndef DCG01_RAW_FRAME_CUSTODY_PATH_H
#define DCG01_RAW_FRAME_CUSTODY_PATH_H

// Derive local diagnostic custody only from the existing admitted manifest.
// This does not accept a journal-output environment override.
#include "raw_frame_journal.h"

#include <openssl/evp.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace dcg01_raw
{
namespace custody
{
static const size_t kAdmittedManifestPathBytes = 512;
static const size_t kAdmittedManifestMaxBytes = 262144;

static bool SameManifestStat(const struct stat& a, const struct stat& b)
{
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
        a.st_mode == b.st_mode && a.st_uid == b.st_uid &&
        a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
        a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}

static bool ValidPathComponent(const char* path, size_t length)
{
    if (length == 0 || (length == 1 && path[0] == static_cast<char>(46)) ||
        (length == 2 && path[0] == static_cast<char>(46) && path[1] == static_cast<char>(46)) ||
        length > NAME_MAX)
        return false;
    for (size_t i = 0; i != length; ++i)
        if (path[i] == static_cast<char>(47)) return false;
    return true;
}

static bool ReadExact(int fd, unsigned char* bytes, size_t length)
{
    size_t offset = 0;
    while (offset != length)
    {
        const ssize_t count = read(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += static_cast<size_t>(count);
    }
    return true;
}

// Opens the admitted manifest parent by walking every component without
// following symlinks. The final directory must be owner-private. The manifest
// itself is reopened, bounded, and hash-checked against the already-admitted
// manifest digest before its directory is returned.
static int OpenAdmittedManifestDirectory(const char* manifestPath,
    const unsigned char expectedDigest[32])
{
    if (!manifestPath || !expectedDigest || manifestPath[0] != static_cast<char>(47))
    { errno = EINVAL; return -1; }
    const size_t pathBytes = strnlen(manifestPath, kAdmittedManifestPathBytes);
    if (pathBytes == 0 || pathBytes >= kAdmittedManifestPathBytes ||
        manifestPath[pathBytes - 1] == static_cast<char>(47))
    { errno = ENAMETOOLONG; return -1; }

    size_t leafStart = pathBytes;
    while (leafStart > 1 && manifestPath[leafStart - 1] != static_cast<char>(47)) --leafStart;
    const size_t leafBytes = pathBytes - leafStart;
    if (!ValidPathComponent(manifestPath + leafStart, leafBytes))
    { errno = EINVAL; return -1; }

    int directoryFd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directoryFd < 0) return -1;
    size_t cursor = 1;
    while (cursor < leafStart)
    {
        const size_t componentStart = cursor;
        while (cursor < leafStart && manifestPath[cursor] != static_cast<char>(47)) ++cursor;
        const size_t componentBytes = cursor - componentStart;
        if (!ValidPathComponent(manifestPath + componentStart, componentBytes))
        { close(directoryFd); errno = EINVAL; return -1; }
        char component[NAME_MAX + 1];
        memcpy(component, manifestPath + componentStart, componentBytes);
        component[componentBytes] = 0;
        const int nextFd = openat(directoryFd, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (nextFd < 0) { close(directoryFd); return -1; }
        if (close(directoryFd) != 0) { close(nextFd); return -1; }
        directoryFd = nextFd;
        ++cursor; // Skip the slash that separated this directory component.
    }

    struct stat directoryInfo;
    if (fstat(directoryFd, &directoryInfo) != 0) { close(directoryFd); return -1; }
    if (!S_ISDIR(directoryInfo.st_mode) || directoryInfo.st_uid != geteuid() ||
        (directoryInfo.st_mode & 0077) != 0)
    { close(directoryFd); errno = EPERM; return -1; }

    char leaf[NAME_MAX + 1];
    memcpy(leaf, manifestPath + leafStart, leafBytes);
    leaf[leafBytes] = 0;
    struct stat linkInfo;
    if (fstatat(directoryFd, leaf, &linkInfo, AT_SYMLINK_NOFOLLOW) != 0)
    { close(directoryFd); return -1; }
    if (!S_ISREG(linkInfo.st_mode) || linkInfo.st_uid != geteuid() ||
        linkInfo.st_nlink != 1 || (linkInfo.st_mode & 0022) != 0 ||
        linkInfo.st_size <= 0 || static_cast<uint64_t>(linkInfo.st_size) > kAdmittedManifestMaxBytes)
    { close(directoryFd); errno = EPERM; return -1; }

    const int manifestFd = openat(directoryFd, leaf,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (manifestFd < 0) { close(directoryFd); return -1; }
    struct stat before;
    bool okay = fstat(manifestFd, &before) == 0 && SameManifestStat(linkInfo, before);
    unsigned char* content = nullptr;
    unsigned char actualDigest[EVP_MAX_MD_SIZE];
    unsigned int actualDigestBytes = 0;
    if (okay)
    {
        content = static_cast<unsigned char*>(malloc(static_cast<size_t>(before.st_size)));
        okay = content != nullptr;
    }
    if (okay) okay = ReadExact(manifestFd, content, static_cast<size_t>(before.st_size));
    struct stat after;
    if (okay) okay = fstat(manifestFd, &after) == 0 && SameManifestStat(before, after);
    if (okay) okay = EVP_Digest(content, static_cast<size_t>(before.st_size),
        actualDigest, &actualDigestBytes, EVP_sha256(), nullptr) == 1 &&
        actualDigestBytes == 32 && memcmp(actualDigest, expectedDigest, 32) == 0;
    if (content) free(content);
    if (close(manifestFd) != 0) okay = false;
    if (!okay)
    {
        const int savedError = errno != 0 ? errno : EINVAL;
        close(directoryFd);
        errno = savedError;
        return -1;
    }
    return directoryFd;
}

static bool FormatArtifactName(const SessionContext& session, char* name, size_t nameBytes)
{
    if (!name || nameBytes == 0 || session.localMember < 1 || session.localMember > 2 ||
        session.peerMember < 1 || session.peerMember > 2 || session.localMember == session.peerMember)
        return false;
    unsigned runAny = 0, incarnationAny = 0;
    char runHex[33], incarnationHex[33];
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i != 16; ++i)
    {
        runAny |= session.runId[i];
        incarnationAny |= session.localIncarnation[i];
        runHex[2 * i] = digits[session.runId[i] >> 4];
        runHex[2 * i + 1] = digits[session.runId[i] & 15];
        incarnationHex[2 * i] = digits[session.localIncarnation[i] >> 4];
        incarnationHex[2 * i + 1] = digits[session.localIncarnation[i] & 15];
    }
    runHex[32] = 0;
    incarnationHex[32] = 0;
    if (runAny == 0 || incarnationAny == 0) return false;
    const int written = snprintf(name, nameBytes,
        "dcg01-frames-node%u-run%s-inc%s.dccj",
        session.localMember, runHex, incarnationHex);
    return written > 0 && static_cast<size_t>(written) < nameBytes &&
        static_cast<size_t>(written) <= NAME_MAX;
}

} // namespace custody
} // namespace dcg01_raw

#endif // DCG01_RAW_FRAME_CUSTODY_PATH_H

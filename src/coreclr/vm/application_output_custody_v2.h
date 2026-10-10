#ifndef DCG01_APPLICATION_OUTPUT_CUSTODY_H
#define DCG01_APPLICATION_OUTPUT_CUSTODY_H

// Candidate-only Linux stdout capture and coordinator-owned artifact publisher.
// Bytes come from the process stdout descriptor, not an expected string.
#include <openssl/sha.h>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace DCG01Output
{
static const size_t kMaxBytes = 16384; // matches the selected native preimage artifact bound
static const int kStdoutFd = STDOUT_FILENO;

// The caller supplies the existing absolute manifest/evidence-record path and
// the authenticated local identity. The leaf binds this capture to that exact
// run and member incarnation without accepting path components from identity.
inline bool BuildArtifactPath(const char* basePath, const unsigned char run[16], unsigned localNode,
                              const unsigned char incarnation[16], char* output, size_t outputBytes)
{
    if (!basePath || basePath[0] != '/' || !run || !incarnation || !output || outputBytes == 0 ||
        localNode != 1)
        return false;
    unsigned runAny = 0, incarnationAny = 0;
    for (size_t i = 0; i < 16; ++i) { runAny |= run[i]; incarnationAny |= incarnation[i]; }
    if (runAny == 0 || incarnationAny == 0) return false;
    const size_t baseBytes = strlen(basePath);
    if (baseBytes == 0 || baseBytes >= PATH_MAX) return false;
    int written = snprintf(output, outputBytes, "%s.application-output.%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x.1.%02x%02x%02x%02x%02x%02x%02x%02x"
        "%02x%02x%02x%02x%02x%02x%02x%02x", basePath,
        run[0],run[1],run[2],run[3],run[4],run[5],run[6],run[7],run[8],run[9],run[10],run[11],run[12],run[13],run[14],run[15],
        incarnation[0],incarnation[1],incarnation[2],incarnation[3],incarnation[4],incarnation[5],incarnation[6],incarnation[7],
        incarnation[8],incarnation[9],incarnation[10],incarnation[11],incarnation[12],incarnation[13],incarnation[14],incarnation[15]);
    return written > 0 && static_cast<size_t>(written) < outputBytes &&
           static_cast<size_t>(written) < PATH_MAX;
}

enum State : uint32_t { Empty = 0, Active = 1, Frozen = 2, Publishing = 3, Published = 4, Failed = 5 };

struct ArtifactInfo
{
    uint64_t artifactId;
    uint64_t contentBytes;
    unsigned char sha256[32];
};

struct IoOps
{
    ssize_t (*writeFn)(int, const void*, size_t);
    ssize_t (*readFn)(int, void*, size_t);
};

inline ssize_t SystemWrite(int fd, const void* p, size_t n) { return ::write(fd, p, n); }
inline ssize_t SystemRead(int fd, void* p, size_t n) { return ::read(fd, p, n); }

#ifdef DCG01_TEST_HOOKS
using RestoreCensusHook = void (*)();
static RestoreCensusHook g_restoreCensusHook = nullptr;
static unsigned g_installDup2Calls = 0;
static unsigned g_installDup2FailAt = 0;
static unsigned g_restoreDup2Calls = 0;
static unsigned g_restoreDup2FailAt = 0;
static unsigned g_setFdCalls = 0;
static unsigned g_setFdFailAt = 0;
#endif

class Capture final
{
public:
    Capture() : state_(Empty), finishRequested_(false), stopRequested_(false), overflow_(false), incomplete_(false),
                teeFailed_(false),
                used_(0), readFd_(-1), savedStdout_(-1), savedStdoutFlags_(-1), savedStdoutDescriptorFlags_(-1),
                savedPalStdoutDescriptorFlags_(-1), threadStarted_(false), palStdoutFd_(-1), originalStdoutStat_(), capturePipeStat_(),
                aliasCount_(0), bytes_(), beginStage_("not-started") {}
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    ~Capture() { StopWithoutPublish(); }

    // Diagnostic-only stage. It never authorizes capture or changes a refusal.
    const char* BeginStage() const { return beginStage_; }

    bool Begin(int palStdoutFd = -1)
    {
        beginStage_ = "state";
        uint32_t expected = Empty;
        if (!state_.compare_exchange_strong(expected, Active, std::memory_order_acq_rel)) return Fail();
        palStdoutFd_ = palStdoutFd;
        // Require an existing stdout before allocating descriptors. If stdout is
        // closed, pipe() could reuse fd 1 and make the capture pipe self-alias.
        beginStage_ = "stdout-descriptor";
        savedStdoutDescriptorFlags_ = fcntl(kStdoutFd, F_GETFD);
        if (savedStdoutDescriptorFlags_ < 0) return Fail();
        beginStage_ = "stdout-fifo";
        if (fstat(kStdoutFd, &originalStdoutStat_) != 0 || !S_ISFIFO(originalStdoutStat_.st_mode))
            return Fail();
        beginStage_ = "stdout-writable";
        const int stdoutFlags = fcntl(kStdoutFd, F_GETFL);
        if (stdoutFlags < 0 || (stdoutFlags & O_ACCMODE) == O_RDONLY) return Fail();
        if (palStdoutFd_ >= 0)
        {
            beginStage_ = "pal-stdout-identity";
            struct stat palStat{};
            const int palFlags = fcntl(palStdoutFd_, F_GETFL);
            savedPalStdoutDescriptorFlags_ = fcntl(palStdoutFd_, F_GETFD);
            if (palStdoutFd_ == kStdoutFd || palFlags < 0 || (palFlags & O_ACCMODE) != O_WRONLY ||
                savedPalStdoutDescriptorFlags_ < 0 || fstat(palStdoutFd_, &palStat) != 0 ||
                !SamePipeObject(originalStdoutStat_, palStat)) return Fail();
        }
        beginStage_ = "preexisting-alias-census";
        if (!NoPreexistingStdoutAliases(originalStdoutStat_, palStdoutFd_)) return Fail();
        int fds[2] = {-1, -1};
        beginStage_ = "pipe-create";
        if (pipe(fds) != 0) return Fail();
        readFd_ = fds[0];
        beginStage_ = "pipe-identity";
        struct stat writerStat{};
        if (fstat(readFd_, &capturePipeStat_) != 0 || fstat(fds[1], &writerStat) != 0 ||
            !S_ISFIFO(capturePipeStat_.st_mode) || !SamePipeObject(capturePipeStat_, writerStat))
        { close(fds[0]); close(fds[1]); readFd_ = -1; return Fail(); }
        beginStage_ = "pipe-flags";
        const int flags = fcntl(readFd_, F_GETFL, 0);
        if (flags < 0 || fcntl(readFd_, F_SETFL, flags | O_NONBLOCK) != 0 ||
            !SetCloseOnExec(fds[0]) || !SetCloseOnExec(fds[1]))
        { close(fds[0]); close(fds[1]); readFd_ = -1; return Fail(); }
        beginStage_ = "stdout-save";
        savedStdout_ = fcntl(kStdoutFd, F_DUPFD_CLOEXEC, 3);
        if (savedStdout_ < 0)
        { close(fds[0]); close(fds[1]); readFd_ = -1; return Fail(); }
        beginStage_ = "stdout-nonblocking";
        savedStdoutFlags_ = fcntl(savedStdout_, F_GETFL);
        if (savedStdoutFlags_ < 0 ||
            fcntl(savedStdout_, F_SETFL, savedStdoutFlags_ | O_NONBLOCK) != 0)
        {
            close(fds[0]); close(fds[1]); close(savedStdout_);
            readFd_ = savedStdout_ = savedStdoutFlags_ = -1; return Fail();
        }
        beginStage_ = "reader-start";
        try { reader_ = std::thread(&Capture::Reader, this); threadStarted_ = true; }
        catch (...)
        {
            if (fcntl(savedStdout_, F_SETFL, savedStdoutFlags_) != 0) teeFailed_.store(true);
            close(fds[0]); close(fds[1]); close(savedStdout_);
            readFd_ = savedStdout_ = savedStdoutFlags_ = -1; return Fail();
        }
        bool palInstalled = false;
        bool stdoutInstalled = false;
        if (palStdoutFd_ >= 0)
        {
            beginStage_ = "pal-redirect";
            if (InstallCaptureDescriptor(fds[1], palStdoutFd_) != palStdoutFd_)
                return AbortBegin(fds[1], palInstalled, stdoutInstalled);
            palInstalled = true;
            beginStage_ = "pal-descriptor-flags";
            if (!SetDescriptorFlags(palStdoutFd_, savedPalStdoutDescriptorFlags_))
                return AbortBegin(fds[1], palInstalled, stdoutInstalled);
        }
        beginStage_ = "stdout-redirect";
        if (InstallCaptureDescriptor(fds[1], kStdoutFd) != kStdoutFd)
        {
            return AbortBegin(fds[1], palInstalled, stdoutInstalled);
        }
        stdoutInstalled = true;
        beginStage_ = "stdout-descriptor-flags";
        if (!SetDescriptorFlags(kStdoutFd, savedStdoutDescriptorFlags_))
            return AbortBegin(fds[1], palInstalled, stdoutInstalled);
        close(fds[1]);
        beginStage_ = "captured";
        return true;
    }

    // Call only after ExecuteMainMethod(waitForOtherThreads=true) has returned.
    // stdout and all known duplicate descriptors are restored before the drainer joins.
    bool Freeze()
    {
        if (state_.load(std::memory_order_acquire) != Active) return Fail();
        bool aliasesOkay = RestoreAndJoin();
        if (!aliasesOkay || incomplete_.load(std::memory_order_acquire) ||
            overflow_.load(std::memory_order_acquire) || teeFailed_.load(std::memory_order_acquire)) return Fail();
        uint32_t expected = Active;
        if (!state_.compare_exchange_strong(expected, Frozen, std::memory_order_acq_rel)) return Fail();
        return true;
    }

    // `finalPath` must be a fresh absolute leaf in a coordinator-owned, non-writable directory.
    // Publication is same-directory pending-file + readback + no-replace hard link.
    bool Publish(const char* finalPath, uint64_t artifactId, ArtifactInfo* info, const IoOps* io = nullptr)
    {
        if (state_.load(std::memory_order_acquire) != Frozen || !finalPath || artifactId == 0 || !info)
            return Fail();
        IoOps calls = io ? *io : IoOps{SystemWrite, SystemRead};
        if (!calls.writeFn || !calls.readFn) return Fail();
        uint32_t expected = Frozen;
        if (!state_.compare_exchange_strong(expected, Publishing, std::memory_order_acq_rel)) return Fail();
        bool ok = PublishFile(finalPath, calls);
        if (!ok) return Fail();
        ArtifactInfo result{};
        result.artifactId = artifactId;
        result.contentBytes = used_;
        if (SHA256(bytes_, used_, result.sha256) == nullptr) return Fail();
        *info = result;
        state_.store(Published, std::memory_order_release);
        return true;
    }

    State CurrentState() const { return static_cast<State>(state_.load(std::memory_order_acquire)); }
    size_t CapturedBytes() const { return used_; }
    const unsigned char* CapturedData() const { return bytes_; }
    bool Overflowed() const { return overflow_.load(std::memory_order_acquire); }
    bool Incomplete() const { return incomplete_.load(std::memory_order_acquire); }
    bool TeeFailed() const { return teeFailed_.load(std::memory_order_acquire); }
    unsigned AliasCount() const { return aliasCount_; }

private:
    static bool SetCloseOnExec(int fd)
    {
        int flags = fcntl(fd, F_GETFD, 0);
        return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
    }

    static bool SamePipeObject(const struct stat& left, const struct stat& right)
    {
        return S_ISFIFO(left.st_mode) && S_ISFIFO(right.st_mode) &&
            left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
            (left.st_mode & S_IFMT) == (right.st_mode & S_IFMT);
    }

    static bool SetDescriptorFlags(int fd, int flags)
    {
        if (flags < 0) return false;
#ifdef DCG01_TEST_HOOKS
        ++g_setFdCalls;
        if (g_setFdFailAt > 0 && g_setFdCalls == g_setFdFailAt) { errno = EIO; return false; }
#endif
        return fcntl(fd, F_SETFD, flags) == 0;
    }

    static int InstallCaptureDescriptor(int source, int target)
    {
#ifdef DCG01_TEST_HOOKS
        ++g_installDup2Calls;
        if (g_installDup2FailAt > 0 && g_installDup2Calls == g_installDup2FailAt)
        { errno = EIO; return -1; }
#endif
        return dup2(source, target);
    }

    static int RestoreCaptureDescriptor(int source, int target, int descriptorFlags)
    {
#ifdef DCG01_TEST_HOOKS
        ++g_restoreDup2Calls;
        if (g_restoreDup2FailAt > 0 && g_restoreDup2Calls == g_restoreDup2FailAt)
        { errno = EIO; return -1; }
#endif
        if (dup2(source, target) != target || !SetDescriptorFlags(target, descriptorFlags)) return -1;
        return target;
    }

    static bool NoPreexistingStdoutAliases(const struct stat& stdoutStat, int palStdoutFd)
    {
        DIR* dir = opendir("/proc/self/fd");
        if (!dir) return false;
        const int directoryFd = dirfd(dir);
        unsigned aliases = 0;
        struct dirent* entry;
        bool readError = false;
        for (;;)
        {
            errno = 0;
            entry = readdir(dir);
            if (entry == nullptr) { readError = errno != 0; break; }
            char* end = nullptr; errno = 0;
            long fdValue = strtol(entry->d_name, &end, 10);
            if (errno || end == entry->d_name || *end || fdValue < 0 || fdValue > INT_MAX ||
                fdValue == directoryFd || fdValue == kStdoutFd)
                continue;
            struct stat candidate{};
            if (fstat(static_cast<int>(fdValue), &candidate) != 0)
            { if (errno == EBADF) continue; closedir(dir); return false; }
            if (SamePipeObject(candidate, stdoutStat))
            {
                if (fdValue == palStdoutFd) continue;
                // Read-only observers (for example the parent harness draining
                // stdout) do not bypass fd 1 writes. Writable aliases do, so a
                // merged stderr or duplicated stdout writer makes this capture
                // boundary incomplete and must fail closed.
                const int flags = fcntl(static_cast<int>(fdValue), F_GETFL);
                if (flags < 0) { closedir(dir); return false; }
                const int accessMode = flags & O_ACCMODE;
                if (accessMode != O_RDONLY) ++aliases;
            }
        }
        int closeResult = closedir(dir);
        return !readError && closeResult == 0 && aliases == 0;
    }

    bool AbortBegin(int pipeWriterFd, bool palInstalled, bool stdoutInstalled)
    {
        if (stdoutInstalled && (savedStdout_ < 0 || RestoreCaptureDescriptor(savedStdout_, kStdoutFd, savedStdoutDescriptorFlags_) != kStdoutFd))
            teeFailed_.store(true, std::memory_order_release);
        if (palInstalled && (savedStdout_ < 0 || RestoreCaptureDescriptor(savedStdout_, palStdoutFd_, savedPalStdoutDescriptorFlags_) != palStdoutFd_))
            teeFailed_.store(true, std::memory_order_release);
        if (pipeWriterFd >= 0 && close(pipeWriterFd) != 0) teeFailed_.store(true, std::memory_order_release);
        finishRequested_.store(true, std::memory_order_release);
        stopRequested_.store(true, std::memory_order_release);
        if (threadStarted_) { reader_.join(); threadStarted_ = false; }
        if (readFd_ >= 0) { close(readFd_); readFd_ = -1; }
        if (savedStdout_ >= 0)
        {
            if (savedStdoutFlags_ < 0 || fcntl(savedStdout_, F_SETFL, savedStdoutFlags_) != 0)
                teeFailed_.store(true, std::memory_order_release);
            close(savedStdout_); savedStdout_ = -1;
        }
        savedStdoutFlags_ = -1;
        savedStdoutDescriptorFlags_ = savedPalStdoutDescriptorFlags_ = -1;
        palStdoutFd_ = -1;
        return Fail();
    }

    static bool StartDeadline(timespec* deadline, long milliseconds)
    {
        if (deadline == nullptr || clock_gettime(CLOCK_MONOTONIC, deadline) != 0) return false;
        deadline->tv_nsec += milliseconds * 1000000L;
        if (deadline->tv_nsec >= 1000000000L)
        { deadline->tv_sec += deadline->tv_nsec / 1000000000L; deadline->tv_nsec %= 1000000000L; }
        return true;
    }

    static bool DeadlineExpired(const timespec& deadline)
    {
        timespec now{};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return true;
        return now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
    }

    static int DeadlineRemainingMs(const timespec& deadline)
    {
        timespec now{};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
        long long milliseconds = static_cast<long long>(deadline.tv_sec - now.tv_sec) * 1000LL +
            (deadline.tv_nsec - now.tv_nsec + 999999L) / 1000000L;
        if (milliseconds <= 0) return 0;
        return milliseconds > INT_MAX ? INT_MAX : static_cast<int>(milliseconds);
    }

    static bool WriteOriginalAll(int fd, const unsigned char* data, size_t length)
    {
        const long kWriteDeadlineMs = 250;
        timespec deadline{};
        if (!StartDeadline(&deadline, kWriteDeadlineMs)) return false;
        size_t offset = 0;
        while (offset < length)
        {
            // Check on every retry, including repeated EINTR.
            if (DeadlineExpired(deadline)) return false;
            ssize_t n = write(fd, data + offset, length - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                int timeout = DeadlineRemainingMs(deadline);
                if (timeout <= 0) return false;
                pollfd writable{fd, POLLOUT, 0};
                int ready = poll(&writable, 1, timeout);
                if (ready < 0 && errno == EINTR) continue;
                if (ready <= 0 || (writable.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return false;
                continue;
            }
            if (n <= 0 || static_cast<size_t>(n) > length - offset) return false;
            offset += static_cast<size_t>(n);
        }
        return true;
    }
    static int OpenDirectoryNoSymlinks(const std::string& path)
    {
        if (path.empty() || path[0] != '/') return -1;
        int current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (current < 0) return -1;
        size_t offset = 1;
        while (offset < path.size())
        {
            while (offset < path.size() && path[offset] == '/') ++offset;
            if (offset == path.size()) break;
            size_t end = path.find('/', offset);
            if (end == std::string::npos) end = path.size();
            std::string component = path.substr(offset, end - offset);
            if (component == ".") { offset = end; continue; }
            if (component == ".." || component.empty()) { close(current); return -1; }
            int next = openat(current, component.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (next < 0) { close(current); return -1; }
            if (close(current) != 0) { close(next); return -1; }
            current = next;
            offset = end;
        }
        return current;
    }

    bool RestoreAndJoin()
    {
        bool okay = true;
        // Confirm stdout still points to the capture pipe. Redirected/closed stdout is unsupported.
        struct stat current{};
        if (fstat(kStdoutFd, &current) != 0 || !SamePipeObject(current, capturePipeStat_))
            okay = false;
        unsigned aliases = 0;
        bool palAliasSeen = palStdoutFd_ < 0;
        DIR* dir = opendir("/proc/self/fd");
        if (!dir) okay = false;
        if (dir)
        {
            const int dirfdValue = dirfd(dir);
            struct dirent* entry;
            bool readError = false;
            for (;;)
            {
                errno = 0;
                entry = readdir(dir);
                if (entry == nullptr) { readError = errno != 0; break; }
                char* end = nullptr; errno = 0;
                long fdValue = strtol(entry->d_name, &end, 10);
                if (errno || end == entry->d_name || *end || fdValue < 0 || fdValue > INT_MAX ||
                    fdValue == dirfdValue || fdValue == readFd_ || fdValue == kStdoutFd || fdValue == savedStdout_)
                    continue;
                struct stat candidate{};
                if (fstat(static_cast<int>(fdValue), &candidate) != 0)
                { if (errno != EBADF) okay = false; continue; }
                if (SamePipeObject(candidate, capturePipeStat_))
                {
                    if (fdValue == palStdoutFd_)
                    { palAliasSeen = true; continue; }
                    const int flags = fcntl(static_cast<int>(fdValue), F_GETFL);
                    if (flags < 0) { okay = false; continue; }
                    // Read-only observers do not write into the capture pipe. Preserve them.
                    if ((flags & O_ACCMODE) == O_RDONLY) continue;
                    ++aliases;
                    // Put any writable duplicate on the original diagnostic stream before capture closes.
                    const int descriptorFlags = fcntl(static_cast<int>(fdValue), F_GETFD);
                    if (descriptorFlags < 0 || savedStdout_ < 0 ||
                        RestoreCaptureDescriptor(savedStdout_, static_cast<int>(fdValue), descriptorFlags) != fdValue) okay = false;
                }
            }
            if (readError) okay = false;
            if (closedir(dir) != 0) okay = false;
        }
        if (palStdoutFd_ >= 0)
        {
            struct stat palCurrent{};
            if (!palAliasSeen || fstat(palStdoutFd_, &palCurrent) != 0 ||
                !SamePipeObject(palCurrent, capturePipeStat_) || savedStdout_ < 0 ||
                RestoreCaptureDescriptor(savedStdout_, palStdoutFd_, savedPalStdoutDescriptorFlags_) != palStdoutFd_)
                okay = false;
        }
#ifdef DCG01_TEST_HOOKS
        if (g_restoreCensusHook != nullptr) g_restoreCensusHook();
#endif
        aliasCount_ = aliases;
        // Current fixture uses one lazy Console.Out duplicate. More than one indicates
        // an unsupported extra OpenStandardOutput/dup writer for this bounded profile.
        if (aliases > 1) okay = false;
        finishRequested_.store(true, std::memory_order_release);
        if (savedStdout_ < 0 || RestoreCaptureDescriptor(savedStdout_, kStdoutFd, savedStdoutDescriptorFlags_) != kStdoutFd) okay = false;
        finishRequested_.store(true, std::memory_order_release);
        stopRequested_.store(true, std::memory_order_release);
        if (threadStarted_)
        {
            reader_.join(); threadStarted_ = false;
        }
        // The reader tees through savedStdout_; keep it open until all buffered
        // capture bytes have been drained and forwarded.
        if (savedStdout_ >= 0)
        {
            if (savedStdoutFlags_ < 0 || fcntl(savedStdout_, F_SETFL, savedStdoutFlags_) != 0) okay = false;
            if (close(savedStdout_) != 0) okay = false;
            savedStdout_ = -1; savedStdoutFlags_ = -1;
            savedStdoutDescriptorFlags_ = savedPalStdoutDescriptorFlags_ = -1;
        }
        palStdoutFd_ = -1;
        if (readFd_ >= 0) { close(readFd_); readFd_ = -1; }
        return okay;
    }

    void Reader()
    {
        // A broken or prematurely closed stdout consumer must fail capture, not
        // deliver the process-default SIGPIPE from this helper thread.
        sigset_t blockedSignals;
        const bool sigpipeBlocked = sigemptyset(&blockedSignals) == 0 &&
            sigaddset(&blockedSignals, SIGPIPE) == 0 &&
            pthread_sigmask(SIG_BLOCK, &blockedSignals, nullptr) == 0;
        if (!sigpipeBlocked) teeFailed_.store(true, std::memory_order_release);
        unsigned char block[4096];
        unsigned stopPollsWithoutEof = 0;
        bool stopDeadlineSet = false;
        timespec stopDeadline{};
        for (;;)
        {
            if (stopRequested_.load(std::memory_order_acquire))
            {
                if (!stopDeadlineSet)
                {
                    if (!StartDeadline(&stopDeadline, 250))
                    { incomplete_.store(true, std::memory_order_release); return; }
                    stopDeadlineSet = true;
                }
                if (DeadlineExpired(stopDeadline))
                { incomplete_.store(true, std::memory_order_release); return; }
            }
            pollfd p{readFd_, POLLIN, 0};
            int ready = poll(&p, 1, 10);
            if (ready < 0)
            {
                if (errno == EINTR) continue;
                incomplete_.store(true, std::memory_order_release); return;
            }
            bool drained = false;
            if (ready > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR)))
            {
                for (;;)
                {
                    if (stopRequested_.load(std::memory_order_acquire))
                    {
                        if (!stopDeadlineSet)
                        {
                            if (!StartDeadline(&stopDeadline, 250))
                            { incomplete_.store(true, std::memory_order_release); return; }
                            stopDeadlineSet = true;
                        }
                        if (DeadlineExpired(stopDeadline))
                        { incomplete_.store(true, std::memory_order_release); return; }
                    }
                    ssize_t n = read(readFd_, block, sizeof(block));
                    if (n > 0)
                    {
                        drained = true;
                        // Tee each captured byte sequence to the original stdout
                        // so the diagnostic hook preserves the host's output.
                        // Continue draining after a tee error to avoid blocking
                        // writers; Freeze will fail closed on teeFailed_.
                        const bool overCap = static_cast<size_t>(n) > kMaxBytes - used_;
                        if (overCap)
                            overflow_.store(true, std::memory_order_release);
                        if (sigpipeBlocked && !teeFailed_.load(std::memory_order_acquire) &&
                            !WriteOriginalAll(savedStdout_, block, static_cast<size_t>(n)))
                            teeFailed_.store(true, std::memory_order_release);
                        if (!overCap)
                        { memcpy(bytes_ + used_, block, static_cast<size_t>(n)); used_ += static_cast<size_t>(n); }
                        if (stopDeadlineSet && DeadlineExpired(stopDeadline))
                        { incomplete_.store(true, std::memory_order_release); return; }
                        continue;
                    }
                    if (n == 0)
                    {
                        if (!finishRequested_.load(std::memory_order_acquire))
                            incomplete_.store(true, std::memory_order_release);
                        return;
                    }
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    incomplete_.store(true, std::memory_order_release); return;
                }
            }
            if (stopRequested_.load(std::memory_order_acquire))
            {
                // Restoration closed fd 1 and every known writer before stop was set.
                // Retry once if the first poll raced the resulting EOF; a writer
                // that escaped the census or a persistent poll/read condition is incomplete.
                if (!drained)
                {
                    if (++stopPollsWithoutEof > 1)
                    {
                        incomplete_.store(true, std::memory_order_release);
                        return;
                    }
                }
                else stopPollsWithoutEof = 0;
            }
        }
    }

    bool RestoreFailureOnly()
    {
        return RestoreAndJoin();
    }

    void StopWithoutPublish()
    {
        if (threadStarted_ || savedStdout_ >= 0) RestoreFailureOnly();
    }

    bool Fail()
    {
        state_.store(Failed, std::memory_order_release);
        return false;
    }

    bool PublishFile(const char* path, const IoOps& io)
    {
        const size_t pathLen = strlen(path);
        if (path[0] != '/' || pathLen == 0 || pathLen >= PATH_MAX) return false;
        const char* slash = strrchr(path, '/');
        if (!slash || slash == path || slash[1] == '\0') return false;
        std::string directory(path, static_cast<size_t>(slash - path));
        std::string leaf(slash + 1);
        if (leaf == "." || leaf == ".." || leaf.find('/') != std::string::npos) return false;
        // Walk every directory component with O_NOFOLLOW. O_NOFOLLOW on a
        // single open(path) would protect only the final component and could
        // still traverse a symlink in an ancestor.
        int dirfdValue = OpenDirectoryNoSymlinks(directory);
        if (dirfdValue < 0) return false;
        struct stat directoryStat{};
        if (fstat(dirfdValue, &directoryStat) != 0 || !S_ISDIR(directoryStat.st_mode) ||
            directoryStat.st_uid != geteuid() || (directoryStat.st_mode & 0022) != 0)
        { close(dirfdValue); return false; }
        static std::atomic<uint64_t> pendingSequence(0);
        char pending[NAME_MAX + 1];
        const int pendingLen = snprintf(pending, sizeof(pending), ".%s.pending.%lld.%llu", leaf.c_str(),
            static_cast<long long>(getpid()), static_cast<unsigned long long>(pendingSequence.fetch_add(1)+1));
        if (pendingLen <= 0 || static_cast<size_t>(pendingLen) >= sizeof(pending))
        { close(dirfdValue); return false; }
        int fd = openat(dirfdValue, pending, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) { close(dirfdValue); return false; }
        bool okay = fchmod(fd, 0600) == 0 && WriteAll(io.writeFn, fd, bytes_, used_) && fsync(fd) == 0;
        struct stat staged{};
        if (okay) okay = fstat(fd, &staged) == 0 && S_ISREG(staged.st_mode) && staged.st_uid == geteuid() &&
                         (staged.st_mode & 0777) == 0600 && static_cast<uint64_t>(staged.st_size) == used_;
        if (close(fd) != 0) okay = false;
        fd = -1;
        if (okay)
        {
            int verifyFd = openat(dirfdValue, pending, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            struct stat observed{};
            if (verifyFd < 0 || fstat(verifyFd, &observed) != 0 || observed.st_dev != staged.st_dev ||
                observed.st_ino != staged.st_ino || observed.st_size != staged.st_size)
                okay = false;
            unsigned char verify[kMaxBytes]; size_t offset = 0;
            while (okay && offset < used_)
            {
                ssize_t n = io.readFn(verifyFd, verify + offset, used_ - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0 || static_cast<size_t>(n) > used_ - offset) { okay = false; break; }
                offset += static_cast<size_t>(n);
            }
            if (okay && (offset != used_ || memcmp(verify, bytes_, used_) != 0)) okay = false;
            if (verifyFd >= 0 && close(verifyFd) != 0) okay = false;
        }
        // Recheck the staging name against the descriptor identity immediately before
        // publication. The directory descriptor pins the parent directory throughout.
        struct stat stagedName{};
        if (okay) okay = fstatat(dirfdValue, pending, &stagedName, AT_SYMLINK_NOFOLLOW) == 0 &&
                         S_ISREG(stagedName.st_mode) && stagedName.st_dev == staged.st_dev &&
                         stagedName.st_ino == staged.st_ino && stagedName.st_size == staged.st_size;
        bool linked = false;
        if (okay)
        {
            if (linkat(dirfdValue, pending, dirfdValue, leaf.c_str(), 0) != 0) okay = false;
            else linked = true;
        }
        if (okay)
        {
            struct stat finalStat{};
            if (fstatat(dirfdValue, leaf.c_str(), &finalStat, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(finalStat.st_mode) || finalStat.st_dev != staged.st_dev ||
                finalStat.st_ino != staged.st_ino || finalStat.st_size != staged.st_size)
                okay = false;
            int finalFd = okay ? openat(dirfdValue, leaf.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
            struct stat opened{};
            if (okay && (finalFd < 0 || fstat(finalFd, &opened) != 0 || opened.st_dev != staged.st_dev ||
                         opened.st_ino != staged.st_ino || opened.st_size != staged.st_size))
                okay = false;
            unsigned char finalBytes[kMaxBytes]; size_t offset = 0;
            while (okay && offset < used_)
            {
                ssize_t n = io.readFn(finalFd, finalBytes + offset, used_ - offset);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0 || static_cast<size_t>(n) > used_ - offset) { okay = false; break; }
                offset += static_cast<size_t>(n);
            }
            if (okay && (offset != used_ || memcmp(finalBytes, bytes_, used_) != 0)) okay = false;
            if (finalFd >= 0 && close(finalFd) != 0) okay = false;
        }
        if (okay && fsync(dirfdValue) != 0) okay = false;
        if (!okay && linked) unlinkat(dirfdValue, leaf.c_str(), 0);
        if (unlinkat(dirfdValue, pending, 0) != 0) okay = false;
        if (close(dirfdValue) != 0) okay = false;
        return okay;
    }

    static bool WriteAll(ssize_t (*writeFn)(int,const void*,size_t), int fd,
        const unsigned char* data, size_t length)
    {
        size_t offset = 0;
        while (offset < length)
        {
            ssize_t n = writeFn(fd, data + offset, length - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0 || static_cast<size_t>(n) > length - offset) return false;
            offset += static_cast<size_t>(n);
        }
        return true;
    }

    std::atomic<uint32_t> state_;
    std::atomic<bool> finishRequested_;
    std::atomic<bool> stopRequested_;
    std::atomic<bool> overflow_;
    std::atomic<bool> incomplete_;
    std::atomic<bool> teeFailed_;
    size_t used_; // reader-thread-owned until joined
    int readFd_;
    int savedStdout_;
    int savedStdoutFlags_;
    int savedStdoutDescriptorFlags_;
    int savedPalStdoutDescriptorFlags_;
    std::thread reader_;
    bool threadStarted_;
    int palStdoutFd_;
    struct stat originalStdoutStat_;
    struct stat capturePipeStat_;
    unsigned aliasCount_;
    unsigned char bytes_[kMaxBytes];
    const char* beginStage_; // Used only by the calling Main thread.
};

} // namespace DCG01Output
#endif

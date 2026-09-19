#include "common/sys_io.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#if defined(__linux__)
#include <sys/syscall.h>
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#endif

namespace protector {

namespace {

constexpr uint64_t kMaxWholeFile = 1024ull * 1024ull * 1024ull; // 1 GiB

#if defined(__linux__)

static long sys_openat_ro(const char* path) {
    for (;;) {
        long fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
        if (fd < 0 && errno == EINTR) {
            continue;
        }
        return fd;
    }
}

static long sys_close_nr(int fd) {
    return syscall(__NR_close, fd);
}

static long sys_read_nr(int fd, void* buf, size_t n) {
    for (;;) {
        long r = syscall(__NR_read, fd, buf, n);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return r;
    }
}

static int sys_seek(int fd, uint64_t off) {
#if defined(__LP64__)
    for (;;) {
        long r = syscall(__NR_lseek, fd, static_cast<off_t>(off), SEEK_SET);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return (r < 0) ? -1 : 0;
    }
#elif defined(__NR__llseek)
    for (;;) {
        int64_t result = 0;
        long r = syscall(__NR__llseek, fd,
                         static_cast<unsigned long>(off >> 32),
                         static_cast<unsigned long>(off),
                         &result, SEEK_SET);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return (r < 0) ? -1 : 0;
    }
#else
    for (;;) {
        long r = syscall(__NR_lseek, fd, static_cast<off_t>(off), SEEK_SET);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return (r < 0) ? -1 : 0;
    }
#endif
}

static int sys_fstat_nr(int fd, struct stat* st) {
#if !defined(__LP64__) && defined(__NR_fstat64)
    return static_cast<int>(syscall(__NR_fstat64, fd, st));
#else
    return static_cast<int>(syscall(__NR_fstat, fd, st));
#endif
}

#else

static long sys_openat_ro(const char* path) {
    return open(path, O_RDONLY | O_CLOEXEC);
}
static long sys_close_nr(int fd) { return close(fd); }
static long sys_read_nr(int fd, void* buf, size_t n) { return read(fd, buf, n); }
static int sys_seek(int fd, uint64_t off) {
    return lseek(fd, static_cast<off_t>(off), SEEK_SET) < 0 ? -1 : 0;
}
static int sys_fstat_nr(int fd, struct stat* st) { return fstat(fd, st); }

#endif

static bool read_loop(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        long r = sys_read_nr(fd, p + got, n - got);
        if (r <= 0) {
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
}

} // namespace

int sys_open_ro(const char* path) {
    if (path == nullptr || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    long fd = sys_openat_ro(path);
    return static_cast<int>(fd);
}

int sys_close_fd(int fd) {
    if (fd < 0) return 0;
    return static_cast<int>(sys_close_nr(fd));
}

bool sys_fd_size(int fd, uint64_t* size) {
    if (fd < 0 || size == nullptr) return false;
    struct stat st {};
    if (sys_fstat_nr(fd, &st) != 0 || st.st_size < 0) {
        return false;
    }
    *size = static_cast<uint64_t>(st.st_size);
    return true;
}

bool sys_pread_all(int fd, uint64_t off, void* buf, size_t n) {
    if (fd < 0 || buf == nullptr) return false;
    if (n == 0) return true;
    if (sys_seek(fd, off) != 0) return false;
    return read_loop(fd, buf, n);
}

bool sys_read_file(const char* path, std::vector<uint8_t>& out) {
    out.clear();
    int fd = sys_open_ro(path);
    if (fd < 0) return false;
    uint64_t size = 0;
    if (!sys_fd_size(fd, &size) || size == 0 || size > kMaxWholeFile) {
        sys_close_fd(fd);
        return false;
    }
    out.resize(static_cast<size_t>(size));
    bool ok = sys_pread_all(fd, 0, out.data(), out.size());
    sys_close_fd(fd);
    if (!ok) {
        out.clear();
        return false;
    }
    return true;
}

bool sys_read_file(const char* path, std::string& out) {
    out.clear();
    std::vector<uint8_t> buf;
    if (!sys_read_file(path, buf)) {
        return false;
    }
    out.assign(reinterpret_cast<const char*>(buf.data()), buf.size());
    memset(buf.data(), 0, buf.size());
    return true;
}

} // namespace protector

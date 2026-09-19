#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace protector {

/**
 * Read protector assets without libc {@code fopen}/{@code ifstream}/{@code pread}.
 * Uses {@code openat}/{@code read}/{@code lseek}/{@code fstat}/{@code close}
 * syscalls. Not a global I/O replacement.
 */

int sys_open_ro(const char* path);
int sys_close_fd(int fd);
bool sys_fd_size(int fd, uint64_t* size);
bool sys_pread_all(int fd, uint64_t off, void* buf, size_t n);

/** Whole-file read. Empty path or unreadable → false and {@code out} cleared. */
bool sys_read_file(const char* path, std::vector<uint8_t>& out);
bool sys_read_file(const char* path, std::string& out);

} // namespace protector

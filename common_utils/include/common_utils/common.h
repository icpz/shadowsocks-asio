#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef WINDOWS

#define setenv(key, val, ovr) _putenv_s(key, val)

#define __START_PACKED __pragma(pack(push, 1))
#define __END_PACKED   __pragma(pack(pop))
#define __PACKED
#define __SFINIT(member, ...) __VA_ARGS__

#include <stdint.h>
using ssize_t = ptrdiff_t;

#else // WINDOWS

#define __START_PACKED
#define __END_PACKED
#define __PACKED       __attribute__((__packed__))
#define __SFINIT(member, ...) member = __VA_ARGS__

#endif // WINDOWS

#ifdef LINUX

#define SIGINFO SIGUSR1

#endif // LINUX

#include <gflags/gflags.h>
#include <glog/logging.h>

void InitialLogLevel(const char *argv0, int verbose);

#endif


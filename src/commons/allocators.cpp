// Copyright (c) 2014-2015 The SXL developers
// Copyright (c) 2019 The NVA Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "commons/allocators.h"

#include <limits.h>  // for PAGESIZE
#include <sys/mman.h>
#include <unistd.h>  // for sysconf

LockedPageManager *LockedPageManager::_instance = NULL;
boost::once_flag LockedPageManager::init_flag   = BOOST_ONCE_INIT;

/** Determine system page size in bytes */
static inline size_t GetSystemPageSize() {
    size_t page_size;
#if defined(PAGESIZE)  // defined in limits.h
    page_size = PAGESIZE;
#else  // assume some POSIX OS
    page_size = sysconf(_SC_PAGESIZE);
#endif
    return page_size;
}

bool MemoryPageLocker::Lock(const void *addr, size_t len) { return mlock(addr, len) == 0; }

bool MemoryPageLocker::Unlock(const void *addr, size_t len) { return munlock(addr, len) == 0; }

LockedPageManager::LockedPageManager() : LockedPageManagerBase<MemoryPageLocker>(GetSystemPageSize()) {}

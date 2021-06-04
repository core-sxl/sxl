// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2019 The NVA Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COMMON_COMPAT_H
#define COMMON_COMPAT_H

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <unistd.h>

typedef u_int SOCKET;
#include "errno.h"
#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEALREADY         EALREADY
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define WSAENOTSOCK         EBADF
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1

inline int32_t myclosesocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return WSAENOTSOCK;

    int ret = close(hSocket);
    hSocket = INVALID_SOCKET;
    return ret;
}
#define closesocket(s)      myclosesocket(s)


#endif

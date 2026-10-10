#pragma once

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

namespace ida_agent::bridge::socket_platform
{
#ifdef __APPLE__
inline constexpr int SendFlags = 0;

inline int Configure(int fd, bool nonblocking)
{
  if ( fd < 0 ) return fd;
  const int no_signal = 1;
  if ( fcntl(fd, F_SETFD, FD_CLOEXEC) == -1
      || (nonblocking && fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
      || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_signal, sizeof(no_signal)) != 0 )
  {
    const int error = errno;
    close(fd);
    errno = error;
    return -1;
  }
  return fd;
}

inline int Create(bool nonblocking = true)
{ return Configure(socket(AF_UNIX, SOCK_STREAM, 0), nonblocking); }

inline int Accept(int listener)
{ return Configure(accept(listener, nullptr, nullptr), true); }

inline bool OwnedPeer(int fd)
{
  uid_t uid{};
  gid_t gid{};
  return getpeereid(fd, &uid, &gid) == 0 && uid == getuid();
}
#else
inline constexpr int SendFlags = MSG_NOSIGNAL;

inline int Create(bool nonblocking = true)
{ return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | (nonblocking ? SOCK_NONBLOCK : 0), 0); }

inline int Accept(int listener)
{ return accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK); }

inline bool OwnedPeer(int fd)
{
  ucred peer{};
  socklen_t size = sizeof(peer);
  return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && peer.uid == getuid();
}
#endif
}

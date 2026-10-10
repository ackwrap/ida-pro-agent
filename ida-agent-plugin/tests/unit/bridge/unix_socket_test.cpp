#include "bridge.hpp"
#include "framing.hpp"
#include "transport/unix_socket_server.hpp"
#include "transport/unix_socket_platform.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}

struct Connection
{
  int fd = -1;
  explicit Connection(const std::string &path)
  {
    fd = ida_agent::bridge::socket_platform::Create(false);
    Require(fd >= 0, "socket failed");
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    Require(path.size() < sizeof(address.sun_path), "path too long");
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1);
    Require(connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0, "connect failed");
  }
  ~Connection() { if ( fd >= 0 ) close(fd); }
  void Send(const std::string &payload, bool fragmented = false)
  {
    auto header = ida_agent::rpc::BuildResponseFrameHeader(static_cast<std::uint32_t>(payload.size()));
    header[3] = 'P';
    std::string frame(reinterpret_cast<const char *>(header.data()), header.size());
    frame += payload;
    std::size_t offset = 0;
    while ( offset < frame.size() )
    {
      const auto count = send(fd, frame.data() + offset, fragmented ? 1 : frame.size() - offset,
          ida_agent::bridge::socket_platform::SendFlags);
      Require(count > 0, "send failed");
      offset += static_cast<std::size_t>(count);
    }
  }
  nlohmann::json Receive()
  {
    std::array<unsigned char, 9> header{};
    Require(recv(fd, header.data(), header.size(), MSG_WAITALL) == 9, "response header missing");
    Require(std::memcmp(header.data(), "IMCR\1", 5) == 0, "bad response header");
    const std::size_t size = (std::size_t(header[5]) << 24) | (std::size_t(header[6]) << 16)
        | (std::size_t(header[7]) << 8) | header[8];
    Require(size > 0 && size <= ida_agent::rpc::MaxMessageBytes, "bad response size");
    std::string payload(size, '\0');
    Require(recv(fd, payload.data(), size, MSG_WAITALL) == static_cast<ssize_t>(size), "response truncated");
    return nlohmann::json::parse(payload);
  }
};
}

int main()
{
  using namespace ida_agent;
  char temporary[] = "/tmp/ida-unix-unit-XXXXXX";
  Require(mkdtemp(temporary) != nullptr, "mkdtemp failed");
  const auto root = std::filesystem::canonical(temporary);
  const auto directory = root / "instances";
  setenv("IDA_AGENT_INSTANCE_DIR", directory.c_str(), 1);
  const bridge::DatabaseMetadata metadata{"test.i64", "test", "9.4", "metapc", "x86_64", 64, false, false, false};
  {
    bridge::Bridge first, second;
    first.Start(metadata);
    second.Start(metadata);
    Require(first.EndpointAddress() != second.EndpointAddress(), "instance socket collision");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    std::size_t published = 0;
    do
    {
      published = 0;
      for ( const auto &entry : std::filesystem::directory_iterator(directory) )
      {
        if ( entry.path().extension() != ".json" ) continue;
        std::ifstream input(entry.path());
        const std::string encoded((std::istreambuf_iterator<char>(input)), {});
        const auto descriptor = rpc::ParseInstanceDescriptor(encoded);
        Require(descriptor.version == 2 && descriptor.endpoint.has_value(), "bad published descriptor");
        ++published;
      }
      if ( published != 2 ) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while ( published != 2 && std::chrono::steady_clock::now() < deadline );
    Require(published == 2, "registry publication failed");
    struct stat permissions{};
    Require(stat(first.EndpointAddress().c_str(), &permissions) == 0 && (permissions.st_mode & 0777) == 0600,
        "socket is not private");
    {
      Connection connection(first.EndpointAddress());
      connection.Send(R"({"method":"hello","params":{"protocol":1,"client":"ida-mcp"}})", true);
      Require(connection.Receive()["instance_id"] == first.InstanceId(), "hello identity mismatch");
      connection.Send(nlohmann::json{{"protocolVersion", "ida-rpc/1"}, {"requestId", "unix-test"},
          {"sessionId", first.InstanceId()}, {"method", "instance.info"}, {"params", nlohmann::json::object()},
          {"timeoutMs", 1000}}.dump(), true);
      Require(connection.Receive().contains("result"), "fragmented RPC failed");
    }
    {
      Connection connection(first.EndpointAddress());
      connection.Send(R"({"method":"hello","params":{"protocol":2,"client":"ida-mcp"}})");
      char byte;
      Require(recv(connection.fd, &byte, 1, 0) == 0, "incompatible hello was accepted");
    }
    {
      Connection connection(first.EndpointAddress());
      const unsigned char bad[] = {'I','M','C','P',1,0x7f,0xff,0xff,0xff};
      Require(send(connection.fd, bad, sizeof(bad), bridge::socket_platform::SendFlags) == sizeof(bad), "oversized header send failed");
      char byte;
      Require(recv(connection.fd, &byte, 1, 0) == 0, "oversized frame was accepted");
    }
    // A partial request must never prevent plugin shutdown.
    Connection idle(first.EndpointAddress());
    Require(send(idle.fd, "IM", 2, bridge::socket_platform::SendFlags) == 2, "partial header failed");
    const auto stopped = std::chrono::steady_clock::now();
    first.Stop();
    second.Stop();
    Require(std::chrono::steady_clock::now() - stopped < std::chrono::seconds(2), "shutdown blocked");
    Require(std::filesystem::is_empty(directory), "registry/socket not cleaned up");
  }
  chmod(directory.c_str(), 0755);
  bool refused = false;
  try { bridge::Bridge unsafe; unsafe.Start(metadata); } catch ( const std::exception & ) { refused = true; }
  Require(refused, "non-private directory was accepted");
  std::filesystem::remove_all(root);
  return 0;
}

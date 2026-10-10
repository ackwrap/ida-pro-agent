#include "secure_random.hpp"

#ifdef __APPLE__
#include <cstdlib>
#else
#include <sys/random.h>
#endif
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace ida_agent::bridge
{
void FillSecureRandom(std::uint8_t *output, std::size_t size)
{
  if ( output == nullptr && size != 0 ) throw std::invalid_argument("random output is null");
#ifdef __APPLE__
  if ( size != 0 ) arc4random_buf(output, size);
#else
  while ( size != 0 )
  {
    const auto count = getrandom(output, size, 0);
    if ( count < 0 && errno == EINTR ) continue;
    if ( count <= 0 ) throw std::runtime_error("system random generation failed");
    output += count;
    size -= static_cast<std::size_t>(count);
  }
#endif
}
std::vector<std::uint8_t> SecureRandom(std::size_t size)
{
  std::vector<std::uint8_t> output(size);
  FillSecureRandom(output.data(), size);
  return output;
}
std::string HexEncode(const std::uint8_t *data, std::size_t size)
{
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string output(size * 2, '0');
  for ( std::size_t index = 0; index < size; ++index )
  {
    output[index * 2] = alphabet[data[index] >> 4];
    output[index * 2 + 1] = alphabet[data[index] & 15];
  }
  return output;
}
void SecureWipe(void *data, std::size_t size) noexcept
{
#ifdef __APPLE__
  auto *bytes = static_cast<volatile std::uint8_t *>(data);
  if ( bytes != nullptr ) while ( size-- != 0 ) *bytes++ = 0;
#else
  if ( data != nullptr && size != 0 ) explicit_bzero(data, size);
#endif
}
}

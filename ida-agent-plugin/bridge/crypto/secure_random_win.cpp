#include "crypto/secure_random.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <limits>
#include <stdexcept>

namespace ida_agent::bridge
{

void FillSecureRandom(std::uint8_t *output, std::size_t size)
{
  if ( output == nullptr && size != 0 )
    throw std::invalid_argument("random output buffer is null");
  if ( size > (std::numeric_limits<ULONG>::max)() )
    throw std::invalid_argument("random output request is too large");
  const NTSTATUS status = BCryptGenRandom(
      nullptr,
      output,
      static_cast<ULONG>(size),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if ( !BCRYPT_SUCCESS(status) )
    throw std::runtime_error("system random generation failed");
}

std::vector<std::uint8_t> SecureRandom(std::size_t size)
{
  std::vector<std::uint8_t> output(size);
  FillSecureRandom(output.data(), output.size());
  return output;
}

std::string HexEncode(const std::uint8_t *data, std::size_t size)
{
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string encoded(size * 2, '0');
  for ( std::size_t index = 0; index < size; ++index )
  {
    encoded[index * 2] = alphabet[data[index] >> 4];
    encoded[index * 2 + 1] = alphabet[data[index] & 0x0F];
  }
  return encoded;
}

void SecureWipe(void *data, std::size_t size) noexcept
{
  if ( data != nullptr && size != 0 )
    SecureZeroMemory(data, size);
}

} // namespace ida_agent::bridge

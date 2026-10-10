#include "ai/agent_effect_digest.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace ida_agent::ai
{
namespace
{

std::uint32_t Rotate(std::uint32_t value, unsigned count)
{
  return (value >> count) | (value << (32 - count));
}

constexpr std::array<std::uint32_t, 64> Constants{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

} // namespace

AgentEffectSha256State::AgentEffectSha256State()
    : hash_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
{
}

void AgentEffectSha256State::Transform(const unsigned char *block)
{
  std::array<std::uint32_t, 64> words{};
  for ( std::size_t index = 0; index < 16; ++index )
  {
    words[index] = (static_cast<std::uint32_t>(block[index * 4]) << 24)
        | (static_cast<std::uint32_t>(block[index * 4 + 1]) << 16)
        | (static_cast<std::uint32_t>(block[index * 4 + 2]) << 8)
        | static_cast<std::uint32_t>(block[index * 4 + 3]);
  }
  for ( std::size_t index = 16; index < 64; ++index )
  {
    const auto s0 = Rotate(words[index - 15], 7) ^ Rotate(words[index - 15], 18)
        ^ (words[index - 15] >> 3);
    const auto s1 = Rotate(words[index - 2], 17) ^ Rotate(words[index - 2], 19)
        ^ (words[index - 2] >> 10);
    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
  }
  auto work = hash_;
  for ( std::size_t index = 0; index < 64; ++index )
  {
    const auto s1 = Rotate(work[4], 6) ^ Rotate(work[4], 11) ^ Rotate(work[4], 25);
    const auto choose = (work[4] & work[5]) ^ (~work[4] & work[6]);
    const auto first = work[7] + s1 + choose + Constants[index] + words[index];
    const auto s0 = Rotate(work[0], 2) ^ Rotate(work[0], 13) ^ Rotate(work[0], 22);
    const auto majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
    const auto second = s0 + majority;
    work = {first + second,work[0],work[1],work[2],work[3] + first,work[4],work[5],work[6]};
  }
  for ( std::size_t index = 0; index < hash_.size(); ++index ) hash_[index] += work[index];
}

void AgentEffectSha256State::Update(std::string_view input)
{
  if ( finalized_ ) throw std::logic_error("SHA-256 state is finalized");
  constexpr std::uint64_t maximum_bytes = (std::numeric_limits<std::uint64_t>::max)() / 8;
  if ( total_bytes_ > maximum_bytes || input.size() > maximum_bytes - total_bytes_ )
    throw std::overflow_error("SHA-256 input is too large");
  total_bytes_ += input.size();
  while ( !input.empty() )
  {
    const std::size_t count = (std::min)(buffer_.size() - buffered_, input.size());
    std::memcpy(buffer_.data() + buffered_, input.data(), count);
    buffered_ += count;
    input.remove_prefix(count);
    if ( buffered_ == buffer_.size() )
    {
      Transform(buffer_.data());
      buffered_ = 0;
    }
  }
}

std::string AgentEffectSha256State::Final()
{
  if ( finalized_ ) throw std::logic_error("SHA-256 state is finalized");
  finalized_ = true;
  const std::uint64_t bits = total_bytes_ * 8;
  buffer_[buffered_++] = 0x80;
  if ( buffered_ > 56 )
  {
    std::fill(buffer_.begin() + buffered_, buffer_.end(), 0);
    Transform(buffer_.data());
    buffered_ = 0;
  }
  std::fill(buffer_.begin() + buffered_, buffer_.begin() + 56, 0);
  for ( int shift = 56; shift >= 0; shift -= 8 )
    buffer_[56 + (56 - shift) / 8] = static_cast<unsigned char>(bits >> shift);
  Transform(buffer_.data());
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for ( std::uint32_t value : hash_ ) output << std::setw(8) << value;
  return output.str();
}

std::string AgentEffectSha256(std::string_view input)
{
  AgentEffectSha256State state;
  state.Update(input);
  return state.Final();
}

} // namespace ida_agent::ai

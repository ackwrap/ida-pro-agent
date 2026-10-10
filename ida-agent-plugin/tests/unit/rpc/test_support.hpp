#pragma once

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

inline std::string ReadFixture(std::string_view category, std::string_view name)
{
  const std::filesystem::path path = std::filesystem::path(IDA_AGENT_PROTOCOL_TESTDATA_DIR)
      / category / name;
  std::ifstream input(path, std::ios::binary);
  if ( !input )
    throw std::runtime_error("failed to open fixture: " + path.string());
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

inline void Require(bool condition, std::string_view message)
{
  if ( !condition )
    throw std::runtime_error(std::string(message));
}

template <typename Callback>
void RequireFailure(Callback callback, std::string_view message)
{
  try
  {
    callback();
  }
  catch ( const std::exception & )
  {
    return;
  }
  throw std::runtime_error(std::string(message));
}

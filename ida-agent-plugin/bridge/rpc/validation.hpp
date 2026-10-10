#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace ida_agent::rpc
{

using Json = nlohmann::json;

Json ParseRootObject(std::string_view encoded);
void RequireExactFields(
    const Json &object,
    std::initializer_list<std::string_view> required,
    std::initializer_list<std::string_view> optional = {});
std::string ReadString(const Json &object, std::string_view field);
std::uint64_t ReadUnsigned(const Json &object, std::string_view field);
bool ReadBool(const Json &object, std::string_view field);
const Json &ReadObject(const Json &object, std::string_view field);
std::size_t Utf8CodePointCount(std::string_view value);
void ValidateProtocolVersion(std::string_view version);
void ValidateIdentifier(std::string_view identifier, std::string_view field);
void ValidateMethod(std::string_view method);

} // namespace ida_agent::rpc

#include "validation.hpp"

#include "envelope.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace ida_agent::rpc
{
namespace
{

bool Contains(
    std::initializer_list<std::string_view> fields,
    std::string_view candidate)
{
  return std::find(fields.begin(), fields.end(), candidate) != fields.end();
}

bool IsIdentifierCharacter(unsigned char character)
{
  return (character >= 'a' && character <= 'z')
      || (character >= 'A' && character <= 'Z')
      || (character >= '0' && character <= '9') || character == '.' || character == '_'
      || character == ':' || character == '-';
}

bool IsMethodNamespace(std::string_view value)
{
  constexpr std::string_view namespaces[] = {
      "system", "instance", "database", "function", "string", "decompiler", "xref", "symbol", "type",
      "memory", "patch", "debugger", "ui", "analysis", "changeset", "global", "instruction", "listing",
      "signature", "script", "fixup", "switch", "exception", "source", "name", "comment", "bookmark",
  };
  return std::find(std::begin(namespaces), std::end(namespaces), value) != std::end(namespaces);
}

std::uint32_t ParseWireUint32Token(std::string_view encoded)
{
  if ( encoded.empty() || encoded.front() == '-' )
    throw std::invalid_argument("numeric value must be an unsigned 32-bit integer");

  const std::size_t exponent_separator = encoded.find_first_of("eE");
  const std::string_view mantissa = encoded.substr(0, exponent_separator);
  std::int64_t exponent = 0;
  if ( exponent_separator != std::string_view::npos )
  {
    std::string_view exponent_text = encoded.substr(exponent_separator + 1);
    bool negative_exponent = false;
    if ( !exponent_text.empty() && (exponent_text.front() == '+' || exponent_text.front() == '-') )
    {
      negative_exponent = exponent_text.front() == '-';
      exponent_text.remove_prefix(1);
    }
    if ( exponent_text.empty() )
      throw std::invalid_argument("numeric exponent is invalid");

    constexpr std::int64_t exponent_limit = static_cast<std::int64_t>(MaxMessageBytes) + 16;
    std::int64_t magnitude = 0;
    for ( const char character : exponent_text )
    {
      if ( character < '0' || character > '9' )
        throw std::invalid_argument("numeric exponent is invalid");
      const int digit = character - '0';
      if ( magnitude > (exponent_limit - digit) / 10 )
      {
        throw std::invalid_argument(
            negative_exponent ? "numeric value is fractional" : "numeric value is out of range");
      }
      magnitude = magnitude * 10 + digit;
    }
    exponent = negative_exponent ? -magnitude : magnitude;
  }

  std::string digits;
  digits.reserve(mantissa.size());
  std::size_t fractional_digits = 0;
  bool after_decimal_point = false;
  for ( const char character : mantissa )
  {
    if ( character == '.' )
    {
      if ( after_decimal_point )
        throw std::invalid_argument("numeric value is invalid");
      after_decimal_point = true;
      continue;
    }
    if ( character < '0' || character > '9' )
      throw std::invalid_argument("numeric value is invalid");
    digits.push_back(character);
    if ( after_decimal_point )
      ++fractional_digits;
  }
  if ( digits.empty() )
    throw std::invalid_argument("numeric value is invalid");
  if ( std::all_of(digits.begin(), digits.end(), [](char character) { return character == '0'; }) )
    return 0;

  const std::int64_t scale = exponent - static_cast<std::int64_t>(fractional_digits);
  if ( scale < 0 )
  {
    const std::size_t removed_digits = static_cast<std::size_t>(-scale);
    if ( removed_digits >= digits.size() )
      throw std::invalid_argument("numeric value is fractional");
    const auto suffix = digits.end() - static_cast<std::ptrdiff_t>(removed_digits);
    if ( !std::all_of(suffix, digits.end(), [](char character) { return character == '0'; }) )
      throw std::invalid_argument("numeric value is fractional");
    digits.erase(suffix, digits.end());
  }

  const std::size_t first_significant = digits.find_first_not_of('0');
  digits.erase(0, first_significant);
  if ( scale > 0 )
  {
    if ( digits.size() + static_cast<std::size_t>(scale) > 10 )
      throw std::invalid_argument("numeric value is out of range");
    digits.append(static_cast<std::size_t>(scale), '0');
  }
  if ( digits.size() > 10 || (digits.size() == 10 && digits > "4294967295") )
    throw std::invalid_argument("numeric value is out of range");

  std::uint32_t value = 0;
  const auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, 10);
  if ( result.ec != std::errc{} || result.ptr != digits.data() + digits.size() )
    throw std::invalid_argument("numeric value is out of range");
  return value;
}

class WireNumberValidator final : public nlohmann::json_sax<Json>
{
public:
  bool null() override { return ConsumeScalar(); }
  bool boolean(bool) override { return ConsumeScalar(); }

  bool number_integer(number_integer_t value) override
  {
    const bool constrained = IsConstrainedIntegerPath(ConsumeValuePath());
    if ( !constrained )
      return true;
    if ( value < 0 || static_cast<number_unsigned_t>(value) > std::numeric_limits<std::uint32_t>::max() )
    {
      error = "numeric value must be an unsigned 32-bit integer";
      return false;
    }
    return true;
  }

  bool number_unsigned(number_unsigned_t value) override
  {
    const bool constrained = IsConstrainedIntegerPath(ConsumeValuePath());
    if ( !constrained )
      return true;
    if ( value > std::numeric_limits<std::uint32_t>::max() )
    {
      error = "numeric value must be an unsigned 32-bit integer";
      return false;
    }
    return true;
  }

  bool number_float(number_float_t, const string_t &encoded) override
  {
    const bool constrained = IsConstrainedIntegerPath(ConsumeValuePath());
    if ( !constrained )
      return true;
    try
    {
      static_cast<void>(ParseWireUint32Token(encoded));
      return true;
    }
    catch ( const std::exception &exception )
    {
      error = exception.what();
      return false;
    }
  }

  bool string(string_t &) override { return ConsumeScalar(); }
  bool binary(binary_t &) override { return ConsumeScalar(); }
  bool start_object(std::size_t) override { return StartContainer(true); }

  bool key(string_t &value) override
  {
    if ( stack.empty() || !stack.back().object )
    {
      error = "object key occurred outside an object";
      return false;
    }
    stack.back().pending_key = value;
    stack.back().has_pending_key = true;
    return true;
  }

  bool end_object() override { return EndContainer(true); }
  bool start_array(std::size_t) override { return StartContainer(false); }
  bool end_array() override { return EndContainer(false); }

  bool parse_error(
      std::size_t,
      const std::string &,
      const nlohmann::detail::exception &exception) override
  {
    error = exception.what();
    return false;
  }

  std::string error;

private:
  struct Frame
  {
    bool object;
    std::string path;
    std::string pending_key;
    bool has_pending_key = false;
  };

  static bool IsConstrainedIntegerPath(std::string_view path)
  {
    return path == "/timeoutMs" || path == "/version" || path == "/pid"
        || path == "/bitness" || path == "/capabilities/address_bits"
        || path == "/capabilities/addressBits";
  }

  std::string ConsumeValuePath()
  {
    if ( stack.empty() )
      return {};

    Frame &parent = stack.back();
    if ( !parent.object )
      return parent.path + "/*";
    if ( !parent.has_pending_key )
      return parent.path;

    std::string path = parent.path + "/" + parent.pending_key;
    parent.pending_key.clear();
    parent.has_pending_key = false;
    return path;
  }

  bool ConsumeScalar()
  {
    static_cast<void>(ConsumeValuePath());
    return true;
  }

  bool StartContainer(bool object)
  {
    const std::string path = stack.empty() ? std::string{} : ConsumeValuePath();
    stack.push_back(Frame{object, path, {}, false});
    return true;
  }

  bool EndContainer(bool object)
  {
    if ( stack.empty() || stack.back().object != object )
    {
      error = "JSON container nesting is invalid";
      return false;
    }
    stack.pop_back();
    return true;
  }

  std::vector<Frame> stack;
};

} // namespace

Json ParseRootObject(std::string_view encoded)
{
  if ( encoded.empty() )
    throw std::invalid_argument("message is empty");
  if ( encoded.size() > MaxMessageBytes )
    throw std::invalid_argument("message exceeds size limit");

  WireNumberValidator number_validator;
  if ( !Json::sax_parse(encoded.begin(), encoded.end(), &number_validator) )
  {
    throw std::invalid_argument(
        number_validator.error.empty() ? "invalid JSON" : number_validator.error);
  }

  Json root;
  try
  {
    root = Json::parse(encoded.begin(), encoded.end());
  }
  catch ( const Json::exception &error )
  {
    throw std::invalid_argument(std::string("invalid JSON: ") + error.what());
  }
  if ( !root.is_object() )
    throw std::invalid_argument("message root must be an object");
  return root;
}

void RequireExactFields(
    const Json &object,
    std::initializer_list<std::string_view> required,
    std::initializer_list<std::string_view> optional)
{
  if ( !object.is_object() )
    throw std::invalid_argument("value must be an object");

  for ( const std::string_view field : required )
  {
    if ( !object.contains(std::string(field)) )
      throw std::invalid_argument("required field is missing: " + std::string(field));
  }
  for ( const auto &[field, value] : object.items() )
  {
    static_cast<void>(value);
    if ( !Contains(required, field) && !Contains(optional, field) )
      throw std::invalid_argument("unknown field: " + field);
  }
}

std::string ReadString(const Json &object, std::string_view field)
{
  const Json &value = object.at(std::string(field));
  if ( !value.is_string() )
    throw std::invalid_argument(std::string(field) + " must be a string");
  return value.get<std::string>();
}

std::uint64_t ReadUnsigned(const Json &object, std::string_view field)
{
  const Json &value = object.at(std::string(field));
  if ( value.is_number_unsigned() )
    return value.get<std::uint64_t>();
  if ( value.is_number_integer() )
  {
    const std::int64_t signed_value = value.get<std::int64_t>();
    if ( signed_value >= 0 )
      return static_cast<std::uint64_t>(signed_value);
  }
  if ( value.is_number_float() )
  {
    const double float_value = value.get<double>();
    if ( std::isfinite(float_value) && float_value >= 0
      && std::trunc(float_value) == float_value
      && float_value <= std::numeric_limits<std::uint32_t>::max() )
    {
      return static_cast<std::uint64_t>(float_value);
    }
  }
  throw std::invalid_argument(std::string(field) + " must be an unsigned integer");
}

bool ReadBool(const Json &object, std::string_view field)
{
  const Json &value = object.at(std::string(field));
  if ( !value.is_boolean() )
    throw std::invalid_argument(std::string(field) + " must be a boolean");
  return value.get<bool>();
}

const Json &ReadObject(const Json &object, std::string_view field)
{
  const Json &value = object.at(std::string(field));
  if ( !value.is_object() )
    throw std::invalid_argument(std::string(field) + " must be an object");
  return value;
}

std::size_t Utf8CodePointCount(std::string_view value)
{
  std::size_t count = 0;
  for ( std::size_t index = 0; index < value.size(); )
  {
    const unsigned char first = static_cast<unsigned char>(value[index]);
    std::size_t width = 0;
    if ( first <= 0x7F )
      width = 1;
    else if ( first >= 0xC2 && first <= 0xDF )
      width = 2;
    else if ( first >= 0xE0 && first <= 0xEF )
      width = 3;
    else if ( first >= 0xF0 && first <= 0xF4 )
      width = 4;
    else
      throw std::invalid_argument("string is not valid UTF-8");

    if ( index + width > value.size() )
      throw std::invalid_argument("string is not valid UTF-8");
    for ( std::size_t continuation = 1; continuation < width; ++continuation )
    {
      const unsigned char byte = static_cast<unsigned char>(value[index + continuation]);
      if ( (byte & 0xC0) != 0x80 )
        throw std::invalid_argument("string is not valid UTF-8");
    }

    if ( width == 3 )
    {
      const unsigned char second = static_cast<unsigned char>(value[index + 1]);
      if ( (first == 0xE0 && second < 0xA0) || (first == 0xED && second > 0x9F) )
        throw std::invalid_argument("string is not valid UTF-8");
    }
    if ( width == 4 )
    {
      const unsigned char second = static_cast<unsigned char>(value[index + 1]);
      if ( (first == 0xF0 && second < 0x90) || (first == 0xF4 && second > 0x8F) )
        throw std::invalid_argument("string is not valid UTF-8");
    }

    index += width;
    ++count;
  }
  return count;
}

void ValidateProtocolVersion(std::string_view version)
{
  if ( version != ProtocolVersion )
    throw std::invalid_argument("unsupported protocolVersion");
}

void ValidateIdentifier(std::string_view identifier, std::string_view field)
{
  if ( identifier.empty() || identifier.size() > 128
    || !std::all_of(identifier.begin(), identifier.end(), IsIdentifierCharacter) )
  {
    throw std::invalid_argument(std::string(field) + " is invalid");
  }
}

void ValidateMethod(std::string_view method)
{
  if ( method.size() < 3 || method.size() > 128 )
    throw std::invalid_argument("method is invalid");
  const std::size_t separator = method.find('.');
  if ( separator == std::string_view::npos || !IsMethodNamespace(method.substr(0, separator)) )
    throw std::invalid_argument("method namespace is invalid");

  const std::string_view operation = method.substr(separator + 1);
  if ( operation.empty() || operation.front() < 'a' || operation.front() > 'z' )
    throw std::invalid_argument("method operation is invalid");
  if ( !std::all_of(operation.begin(), operation.end(), [](unsigned char character)
  {
    return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
        || character == '_';
  }) )
  {
    throw std::invalid_argument("method operation is invalid");
  }
}

} // namespace ida_agent::rpc

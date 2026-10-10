#include "ai/provider_settings_model.hpp"

#include "ai/provider_url.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <unordered_set>
#include <utility>

namespace ida_agent::ai
{
namespace
{

constexpr std::string_view BrowserUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36";
constexpr std::size_t MaxProfiles = 64;
constexpr std::size_t MaxProfileIdLength = 128;
constexpr std::size_t MaxDisplayNameLength = 128;
constexpr std::size_t MaxApiKeyLength = 8192;
constexpr std::size_t MaxModelsPerProfile = 256;
constexpr std::size_t MaxModelIdLength = 256;
constexpr std::size_t MaxHeadersPerProfile = 64;
constexpr std::size_t MaxHeaderNameLength = 256;
constexpr std::size_t MaxHeaderValueLength = 8192;
constexpr std::size_t MaxProxyHostLength = 253;
constexpr std::size_t MaxProxyUsernameLength = 1024;
constexpr std::size_t MaxProxyPasswordLength = 4096;

void Trim(std::string &value)
{
  const std::size_t first = value.find_first_not_of(' ');
  if ( first == std::string::npos )
  {
    value.clear();
    return;
  }
  const std::size_t last = value.find_last_not_of(' ');
  value = value.substr(first, last - first + 1);
}

bool HasControlCharacter(std::string_view value)
{
  return std::any_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return character < 0x20 || character == 0x7f;
      });
}

bool HasCapability(std::string_view capabilities, std::string_view expected)
{
  std::size_t start = 0;
  while ( start <= capabilities.size() )
  {
    const std::size_t comma = capabilities.find(',', start);
    std::string token(capabilities.substr(
        start,
        comma == std::string_view::npos ? std::string_view::npos : comma - start));
    Trim(token);
    std::transform(token.begin(), token.end(), token.begin(), [](unsigned char value)
    {
      return value >= 'A' && value <= 'Z'
          ? static_cast<char>(value - 'A' + 'a')
          : static_cast<char>(value);
    });
    if ( token == expected )
      return true;
    if ( comma == std::string_view::npos )
      break;
    start = comma + 1;
  }
  return false;
}

bool HasWhitespace(std::string_view value)
{
  return std::any_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return character == ' '
            || character == '\t'
            || character == '\n'
            || character == '\r'
            || character == '\f'
            || character == '\v';
      });
}

bool IsDecimalByte(std::string_view value)
{
  if ( value.empty() || value.size() > 3 )
    return false;
  unsigned int parsed = 0;
  for ( const unsigned char character : value )
  {
    if ( character < '0' || character > '9' )
      return false;
    parsed = parsed * 10 + static_cast<unsigned int>(character - '0');
  }
  return parsed <= 255;
}

bool IsIpv4Literal(std::string_view host)
{
  std::size_t offset = 0;
  for ( int part = 0; part < 4; ++part )
  {
    const std::size_t end = part == 3 ? host.size() : host.find('.', offset);
    if ( end == std::string_view::npos
        || !IsDecimalByte(host.substr(offset, end - offset)) )
    {
      return false;
    }
    offset = end + 1;
  }
  return offset == host.size() + 1;
}

bool IsHexGroup(std::string_view value)
{
  if ( value.empty() || value.size() > 4 )
    return false;
  return std::all_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        return (character >= '0' && character <= '9')
            || (character >= 'a' && character <= 'f')
            || (character >= 'A' && character <= 'F');
      });
}

bool CountIpv6Groups(
    std::string_view value,
    bool allow_ipv4_tail,
    std::size_t &groups)
{
  groups = 0;
  if ( value.empty() )
    return true;
  std::size_t offset = 0;
  while ( offset <= value.size() )
  {
    const std::size_t end = value.find(':', offset);
    const std::string_view group = value.substr(
        offset,
        end == std::string_view::npos ? value.size() - offset : end - offset);
    if ( group.find('.') != std::string_view::npos )
    {
      if ( !allow_ipv4_tail
          || end != std::string_view::npos
          || !IsIpv4Literal(group) )
      {
        return false;
      }
      groups += 2;
    }
    else
    {
      if ( !IsHexGroup(group) )
        return false;
      ++groups;
    }
    if ( end == std::string_view::npos )
      return true;
    offset = end + 1;
  }
  return true;
}

bool IsIpv6Literal(std::string_view host)
{
  const std::size_t compressed = host.find("::");
  if ( compressed != std::string_view::npos
      && host.find("::", compressed + 2) != std::string_view::npos )
  {
    return false;
  }

  std::size_t left_groups = 0;
  std::size_t right_groups = 0;
  if ( compressed == std::string_view::npos )
  {
    return CountIpv6Groups(host, true, left_groups) && left_groups == 8;
  }
  const std::string_view left = host.substr(0, compressed);
  const std::string_view right = host.substr(compressed + 2);
  return CountIpv6Groups(left, false, left_groups)
      && CountIpv6Groups(right, true, right_groups)
      && left_groups + right_groups < 8;
}

bool IsDnsName(std::string_view host)
{
  if ( host.empty() || host.size() > MaxProxyHostLength )
    return false;
  std::size_t offset = 0;
  while ( offset < host.size() )
  {
    const std::size_t end = host.find('.', offset);
    const std::string_view label = host.substr(
        offset,
        end == std::string_view::npos ? host.size() - offset : end - offset);
    if ( label.empty()
        || label.size() > 63
        || label.front() == '-'
        || label.back() == '-'
        || !std::all_of(
            label.begin(),
            label.end(),
            [](unsigned char character)
            {
              return (character >= 'a' && character <= 'z')
                  || (character >= 'A' && character <= 'Z')
                  || (character >= '0' && character <= '9')
                  || character == '-';
            }) )
    {
      return false;
    }
    if ( end == std::string_view::npos )
      return true;
    offset = end + 1;
  }
  return false;
}

bool IsValidProxyHost(std::string_view host)
{
  if ( host.empty()
      || host.size() > MaxProxyHostLength
      || HasControlCharacter(host)
      || HasWhitespace(host)
      || host.find_first_of("/@?#") != std::string_view::npos )
  {
    return false;
  }
  if ( host.find(':') != std::string_view::npos )
    return IsIpv6Literal(host);
  const bool looks_like_ipv4 = std::all_of(
      host.begin(),
      host.end(),
      [](unsigned char character)
      {
        return (character >= '0' && character <= '9') || character == '.';
      });
  return looks_like_ipv4 ? IsIpv4Literal(host) : IsDnsName(host);
}

bool IsHttpToken(std::string_view value)
{
  if ( value.empty() || value.size() > MaxHeaderNameLength )
    return false;
  return std::all_of(
      value.begin(),
      value.end(),
      [](unsigned char character)
      {
        const bool alpha_numeric = (character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9');
        constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
        return alpha_numeric || punctuation.find(static_cast<char>(character)) != std::string_view::npos;
      });
}

std::string LowerAscii(std::string_view value)
{
  std::string lowered(value);
  std::transform(
      lowered.begin(),
      lowered.end(),
      lowered.begin(),
      [](unsigned char character)
      {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : static_cast<char>(character);
      });
  return lowered;
}

bool IsForbiddenHeader(std::string_view lowered_name)
{
  constexpr std::array<std::string_view, 5> forbidden{{
      "host",
      "content-length",
      "transfer-encoding",
      "connection",
      "proxy-authorization",
  }};
  return std::find(forbidden.begin(), forbidden.end(), lowered_name) != forbidden.end();
}

std::vector<ProviderHeaderDraft> DefaultHeaders()
{
  return {{"User-Agent", std::string(BrowserUserAgent), true}};
}

bool Matches(const ProviderSettingsDraft &left, const ProviderSettingsDraft &right)
{
  return left.display_name == right.display_name
      && left.protocol == right.protocol
      && left.openai_api_mode == right.openai_api_mode
      && left.base_url == right.base_url
      && left.model == right.model;
}

} // namespace

ProviderSettingsDraft DraftForPreset(ProviderPreset preset)
{
  switch ( preset )
  {
    case ProviderPreset::OpenAI:
      return ProviderSettingsDraft{
          "OpenAI",
          ProviderProtocol::OpenAI,
          OpenAIApiMode::Responses,
          "https://api.openai.com/v1",
          "",
          "",
      };
    case ProviderPreset::Claude:
      return ProviderSettingsDraft{
          "Claude",
          ProviderProtocol::Claude,
          OpenAIApiMode::Responses,
          "https://api.anthropic.com/v1",
          "",
          "",
      };
    case ProviderPreset::Custom:
      return ProviderSettingsDraft{
          "Custom Provider",
          ProviderProtocol::OpenAI,
          OpenAIApiMode::ChatCompletions,
          "",
          "",
          "",
      };
  }
  return {};
}

std::string_view DefaultBrowserUserAgent() noexcept
{
  return BrowserUserAgent;
}

void ApplyDefaultModelMetadata(ProviderModelDraft &model) noexcept
{
  if ( model.context_length == 0 )
    model.context_length = DefaultModelContextLength;
  if ( model.max_output_tokens == 0 )
    model.max_output_tokens = DefaultModelMaxOutputTokens;
  Trim(model.capabilities);
  if ( !HasCapability(model.capabilities, "tools") )
  {
    constexpr std::string_view suffix = ", tools";
    if ( model.capabilities.size() > MaxCapabilitiesLength - suffix.size() )
    {
      const std::size_t comma = model.capabilities.rfind(
          ',', MaxCapabilitiesLength - suffix.size());
      if ( comma == std::string::npos )
        model.capabilities.clear();
      else
        model.capabilities.resize(comma);
      Trim(model.capabilities);
    }
    model.capabilities += model.capabilities.empty() ? "tools" : suffix;
  }
}

ProviderPreset PresetForDraft(const ProviderSettingsDraft &draft)
{
  if ( Matches(draft, DraftForPreset(ProviderPreset::OpenAI)) )
    return ProviderPreset::OpenAI;
  if ( Matches(draft, DraftForPreset(ProviderPreset::Claude)) )
    return ProviderPreset::Claude;
  return ProviderPreset::Custom;
}

void SetProtocol(ProviderSettingsDraft &draft, ProviderProtocol protocol)
{
  draft.protocol = protocol;
}

void NormalizeProviderProxyDraft(ProviderProxyDraft &draft)
{
  Trim(draft.host);
  Trim(draft.username);
  if ( draft.host.size() >= 2
      && draft.host.front() == '['
      && draft.host.back() == ']' )
  {
    draft.host = draft.host.substr(1, draft.host.size() - 2);
  }
}

bool IsValidProviderProxyDraft(const ProviderProxyDraft &draft)
{
  const bool credentials_valid = draft.username.size() <= MaxProxyUsernameLength
      && draft.password.size() <= MaxProxyPasswordLength
      && !HasControlCharacter(draft.username)
      && !HasControlCharacter(draft.password);
  if ( !credentials_valid )
    return false;
  if ( draft.mode == ProviderProxyMode::System
      || draft.mode == ProviderProxyMode::Direct )
  {
    return draft.host.empty()
        && draft.port == 0
        && draft.username.empty()
        && draft.password.empty();
  }
  return draft.mode == ProviderProxyMode::Http
      && IsValidProxyHost(draft.host)
      && draft.port != 0;
}

void NormalizeProviderManagerDraft(ProviderManagerDraft &draft)
{
  Trim(draft.active_profile_id);
  for ( ProviderProfileDraft &profile : draft.profiles )
  {
    Trim(profile.id);
    Trim(profile.settings.display_name);
    Trim(profile.settings.base_url);
    while ( !profile.settings.base_url.empty()
        && profile.settings.base_url.back() == '/' )
    {
      profile.settings.base_url.pop_back();
    }
    Trim(profile.settings.model);
    for ( ProviderModelDraft &model : profile.models )
    {
      Trim(model.id);
      Trim(model.capabilities);
      ApplyDefaultModelMetadata(model);
    }
    for ( ProviderHeaderDraft &header : profile.custom_headers )
    {
      Trim(header.name);
      Trim(header.value);
    }
    NormalizeProviderProxyDraft(profile.proxy);
  }
}

void MergeDiscoveredModels(
    ProviderProfileDraft &profile,
    const std::vector<ProviderModelDraft> &incoming)
{
  for ( const ProviderModelDraft &discovered : incoming )
  {
    ProviderModelDraft discovered_with_defaults = discovered;
    ApplyDefaultModelMetadata(discovered_with_defaults);
    auto existing = std::find_if(
        profile.models.begin(),
        profile.models.end(),
        [&discovered_with_defaults](const ProviderModelDraft &model)
        {
          return model.id == discovered_with_defaults.id;
        });
    if ( existing == profile.models.end() )
    {
      ProviderModelDraft added = std::move(discovered_with_defaults);
      added.enabled = true;
      profile.models.push_back(std::move(added));
      continue;
    }
    if ( existing->capabilities.empty()
        && !discovered_with_defaults.capabilities.empty() )
    {
      existing->capabilities = discovered_with_defaults.capabilities;
    }
    if ( existing->context_length == 0 )
      existing->context_length = discovered_with_defaults.context_length;
    if ( existing->max_output_tokens == 0 )
      existing->max_output_tokens = discovered_with_defaults.max_output_tokens;
  }

  const auto current_default = std::find_if(
      profile.models.begin(),
      profile.models.end(),
      [&profile](const ProviderModelDraft &model)
      {
        return model.id == profile.settings.model && model.enabled;
      });
  if ( current_default != profile.models.end() )
    return;
  const auto first_enabled = std::find_if(
      profile.models.begin(),
      profile.models.end(),
      [](const ProviderModelDraft &model)
      {
        return model.enabled;
      });
  profile.settings.model = first_enabled == profile.models.end()
      ? std::string{}
      : first_enabled->id;
}

bool IsValidDraft(const ProviderSettingsDraft &draft)
{
  const bool protocol_valid = draft.protocol == ProviderProtocol::OpenAI
      || draft.protocol == ProviderProtocol::Claude;
  const bool mode_valid = draft.openai_api_mode == OpenAIApiMode::Responses
      || draft.openai_api_mode == OpenAIApiMode::ChatCompletions;
  return protocol_valid
      && mode_valid
      && !draft.display_name.empty()
      && draft.display_name.size() <= MaxDisplayNameLength
      && !HasControlCharacter(draft.display_name)
      && provider_detail::IsValidBaseUrl(draft.base_url)
      && draft.api_key.size() <= MaxApiKeyLength
      && !HasControlCharacter(draft.api_key)
      && draft.model.size() <= MaxModelIdLength
      && !HasControlCharacter(draft.model);
}

ProviderManagerDraft CreateProviderManagerDraft()
{
  ProviderManagerDraft draft;
  draft.profiles.push_back(
      ProviderProfileDraft{
          "builtin-openai",
          true,
          DraftForPreset(ProviderPreset::OpenAI),
          {},
          DefaultHeaders()});
  draft.profiles.push_back(
      ProviderProfileDraft{
          "builtin-claude",
          true,
          DraftForPreset(ProviderPreset::Claude),
          {},
          DefaultHeaders()});
  draft.active_profile_id = draft.profiles.front().id;
  return draft;
}

ProviderProfileDraft *FindProvider(
    ProviderManagerDraft &draft,
    std::string_view profile_id) noexcept
{
  const auto found = std::find_if(
      draft.profiles.begin(),
      draft.profiles.end(),
      [profile_id](const ProviderProfileDraft &profile)
      {
        return profile.id == profile_id;
      });
  return found == draft.profiles.end() ? nullptr : &*found;
}

const ProviderProfileDraft *FindProvider(
    const ProviderManagerDraft &draft,
    std::string_view profile_id) noexcept
{
  const auto found = std::find_if(
      draft.profiles.begin(),
      draft.profiles.end(),
      [profile_id](const ProviderProfileDraft &profile)
      {
        return profile.id == profile_id;
      });
  return found == draft.profiles.end() ? nullptr : &*found;
}

ProviderProfileDraft *ActiveProvider(ProviderManagerDraft &draft) noexcept
{
  return FindProvider(draft, draft.active_profile_id);
}

const ProviderProfileDraft *ActiveProvider(const ProviderManagerDraft &draft) noexcept
{
  return FindProvider(draft, draft.active_profile_id);
}

std::string AddCustomProvider(ProviderManagerDraft &draft)
{
  std::string profile_id;
  do
  {
    profile_id = "custom-" + std::to_string(draft.next_custom_id++);
  }
  while ( FindProvider(draft, profile_id) != nullptr );

  ProviderSettingsDraft settings = DraftForPreset(ProviderPreset::Custom);
  if ( draft.next_custom_id > 2 )
    settings.display_name += " " + std::to_string(draft.next_custom_id - 1);
  draft.profiles.push_back(
      ProviderProfileDraft{
          profile_id,
          false,
          std::move(settings),
          {},
          DefaultHeaders()});
  return profile_id;
}

bool RemoveCustomProvider(
    ProviderManagerDraft &draft,
    std::string_view profile_id)
{
  const auto found = std::find_if(
      draft.profiles.begin(),
      draft.profiles.end(),
      [profile_id](const ProviderProfileDraft &profile)
      {
        return profile.id == profile_id;
      });
  if ( found == draft.profiles.end() || found->built_in )
    return false;

  const bool removed_active = draft.active_profile_id == found->id;
  draft.profiles.erase(found);
  if ( removed_active )
  {
    draft.active_profile_id = draft.profiles.empty()
        ? std::string{}
        : draft.profiles.front().id;
  }
  return true;
}

bool IsValidManagerDraft(const ProviderManagerDraft &draft)
{
  if ( draft.profiles.empty()
      || draft.profiles.size() > MaxProfiles
      || draft.next_custom_id == 0
      || ActiveProvider(draft) == nullptr )
    return false;

  std::unordered_set<std::string> profile_ids;
  for ( const ProviderProfileDraft &profile : draft.profiles )
  {
    if ( profile.id.empty()
        || profile.id.size() > MaxProfileIdLength
        || HasControlCharacter(profile.id)
        || !profile_ids.insert(profile.id).second
        || !IsValidDraft(profile.settings)
        || !IsValidProviderProxyDraft(profile.proxy)
        || profile.models.size() > MaxModelsPerProfile
        || profile.custom_headers.size() > MaxHeadersPerProfile )
    {
      return false;
    }

    std::unordered_set<std::string> model_ids;
    bool default_found = profile.settings.model.empty();
    for ( const ProviderModelDraft &model : profile.models )
    {
      if ( model.id.empty()
          || model.id.size() > MaxModelIdLength
          || HasControlCharacter(model.id)
          || model.capabilities.size() > MaxCapabilitiesLength
          || HasControlCharacter(model.capabilities)
          || !model_ids.insert(model.id).second )
        return false;
      if ( model.id == profile.settings.model && model.enabled )
        default_found = true;
    }
    if ( !default_found )
      return false;

    std::unordered_set<std::string> header_names;
    for ( const ProviderHeaderDraft &header : profile.custom_headers )
    {
      const std::string lowered_name = LowerAscii(header.name);
      if ( !IsHttpToken(header.name)
          || header.value.size() > MaxHeaderValueLength
          || HasControlCharacter(header.value)
          || IsForbiddenHeader(lowered_name)
          || !header_names.insert(lowered_name).second )
      {
        return false;
      }
    }
  }
  return true;
}

} // namespace ida_agent::ai

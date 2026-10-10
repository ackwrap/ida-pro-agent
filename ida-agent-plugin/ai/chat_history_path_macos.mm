#import <Foundation/Foundation.h>
#include "ai/chat_history_store.hpp"

namespace ida_agent::ai
{
std::optional<std::string> NormalizeDatabaseKey(const std::filesystem::path &idb_path)
{
  if (idb_path.empty() || !idb_path.is_absolute() || idb_path.filename().empty()) return std::nullopt;
  std::error_code error;
  const auto status = std::filesystem::symlink_status(idb_path, error);
  std::filesystem::path path;
  if (status.type() == std::filesystem::file_type::not_found)
  {
    error.clear();
    const auto parent = std::filesystem::canonical(idb_path.parent_path(), error);
    if (error || !std::filesystem::is_directory(parent, error) || error) return std::nullopt;
    path = parent / idb_path.filename();
  }
  else
  {
    if (error || !std::filesystem::is_regular_file(idb_path, error) || error) return std::nullopt;
    path = std::filesystem::canonical(idb_path, error);
    if (error) return std::nullopt;
  }
  @autoreleasepool {
    const auto encoded = path.u8string(), parent = path.parent_path().u8string();
    NSString *text = [[NSString alloc] initWithBytes:encoded.data() length:encoded.size() encoding:NSUTF8StringEncoding];
    NSString *directory = [[NSString alloc] initWithBytes:parent.data() length:parent.size() encoding:NSUTF8StringEncoding];
    if (!text || !directory) return std::nullopt;
    NSNumber *sensitive = nil;
    if (![[NSURL fileURLWithPath:directory isDirectory:YES] getResourceValue:&sensitive
        forKey:NSURLVolumeSupportsCaseSensitiveNamesKey error:nil]) return std::nullopt;
    text = text.precomposedStringWithCanonicalMapping;
    if (!sensitive.boolValue) text = text.lowercaseString;
    NSData *bytes = [text dataUsingEncoding:NSUTF8StringEncoding];
    return std::string(static_cast<const char *>(bytes.bytes), bytes.length);
  }
}
}

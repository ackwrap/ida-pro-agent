#include "ai/agent_file_service.hpp"
#include "ai/agent_effect_digest.hpp"
#include "ai/utf8.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

namespace ida_agent::ai
{
namespace
{
using Json = nlohmann::json;
constexpr std::uint64_t MaxFileSize = 16ULL * 1024 * 1024;
constexpr std::uint64_t MaxTreeBytes = 64ULL * 1024 * 1024;
constexpr std::size_t MaxEntries = 4096;

void Check(bool value, const char *message)
{
  if ( !value ) throw std::runtime_error(message);
}

class Fd final
{
public:
  explicit Fd(int value = -1) : value_(value) {}
  ~Fd() { if ( value_ >= 0 ) close(value_); }
  Fd(Fd &&other) noexcept : value_(std::exchange(other.value_, -1)) {}
  Fd &operator=(Fd &&other) noexcept
  {
    if ( this != &other )
    {
      if ( value_ >= 0 ) close(value_);
      value_ = std::exchange(other.value_, -1);
    }
    return *this;
  }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  int get() const { return value_; }
private:
  int value_;
};

struct Root { Fd fd; std::string path; std::string idb; };

struct stat Info(int fd)
{
  struct stat result{};
  Check(fstat(fd, &result) == 0, "file information unavailable");
  return result;
}

bool Identity(const struct stat &a, const struct stat &b)
{
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino
      && (a.st_mode & S_IFMT) == (b.st_mode & S_IFMT);
}

bool Unchanged(const struct stat &a, const struct stat &b)
{
  return Identity(a, b) && a.st_size == b.st_size && a.st_nlink == b.st_nlink
#ifdef __APPLE__
      && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
      && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
#else
      && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
      && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
#endif
}

std::int64_t ModifiedTimeMs(const struct stat &info)
{
#ifdef __APPLE__
  const auto time = info.st_mtimespec;
#else
  const auto time = info.st_mtim;
#endif
  return time.tv_sec * 1000LL + time.tv_nsec / 1000000;
}

std::string Lower(std::string value)
{
  for ( char &ch : value ) if ( ch >= 'A' && ch <= 'Z' ) ch += 'a' - 'A';
  return value;
}

bool Sensitive(std::string_view value)
{
  const std::string name = Lower(std::string(value));
  static const std::string blocked[]{".git", ".hg", ".svn", ".ssh", ".gnupg",
      ".config", ".cache", ".local", ".idapro", ".aws", ".azure", ".kube",
      ".env", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json"
#ifdef __APPLE__
      , "library", ".ds_store"
#endif
  };
  if ( std::find(std::begin(blocked), std::end(blocked), name) != std::end(blocked)
      || name.rfind(".env.", 0) == 0 || name.rfind("secrets.", 0) == 0 ) return true;
  const auto dot = name.rfind('.');
  if ( dot == std::string::npos ) return false;
  const auto ext = name.substr(dot);
  static const std::string extensions[]{".pem", ".key", ".pfx", ".p12", ".kdbx",
      ".idb", ".i64", ".id0", ".id1", ".id2", ".id3", ".id4", ".id5",
      ".id6", ".id7", ".id8", ".nam", ".til"};
  return std::find(std::begin(extensions), std::end(extensions), ext) != std::end(extensions);
}

std::vector<std::string> Components(std::string_view path, bool empty = false)
{
  if ( path.empty() ) { Check(empty, "empty path"); return {}; }
  Check(path.size() <= MaxAgentFilePathBytes && ValidUtf8(path), "invalid path");
  Check(path.find_first_of("\\:\0", 0, 3) == std::string_view::npos, "invalid path");
  std::vector<std::string> result;
  std::size_t start = 0;
  do
  {
    const auto end = path.find('/', start);
    const auto name = path.substr(start, end == path.npos ? path.size() - start : end - start);
    Check(!name.empty() && name != "." && name != ".." && !Sensitive(name)
        && std::none_of(name.begin(), name.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }),
        "protected or invalid path component");
    result.emplace_back(name);
    if ( end == path.npos ) break;
    start = end + 1;
  } while ( true );
  return result;
}

Fd OpenAt(int parent, const std::string &name, int flags = O_RDONLY)
{
  Fd result(openat(parent, name.c_str(), flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600));
  Check(result.get() >= 0, "cannot open file safely");
  const auto info = Info(result.get());
  Check(S_ISDIR(info.st_mode) || (S_ISREG(info.st_mode) && info.st_nlink == 1),
      "only directories and unshared regular files are allowed");
  return result;
}

Fd AbsoluteDirectory(const std::string &path)
{
  Check(!path.empty() && path.front() == '/', "IDB path must be absolute");
  Fd current(open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  Check(current.get() >= 0, "root unavailable");
  std::size_t start = 1;
  while ( start < path.size() )
  {
    const auto end = path.find('/', start);
    const auto name = path.substr(start, end == path.npos ? path.size() - start : end - start);
    Check(!name.empty() && name != "." && name != ".." && !Sensitive(name), "unsafe IDB root");
    current = OpenAt(current.get(), name, O_RDONLY | O_DIRECTORY);
    if ( end == path.npos ) break;
    start = end + 1;
  }
  return current;
}

bool Within(std::string_view base, std::string_view path)
{
  return path == base || (path.size() > base.size() && path.substr(0, base.size()) == base
      && path[base.size()] == '/');
}

Root CurrentRoot(const AgentFileService::IdbPathProvider &provider)
{
  const auto idb = provider ? provider() : std::string();
  Check(!idb.empty() && idb.front() == '/' && ValidUtf8(idb)
      && idb.find('\0') == idb.npos, "no absolute IDB path");
  const auto full = std::filesystem::path(idb).lexically_normal();
  const auto path = full.parent_path().string();
  Check(path != "/" && path != "/tmp" && path != "/home" && path != "/var/tmp", "unsafe IDB root");
#ifdef __APPLE__
  Check(path != "/private/tmp" && path != "/private/var/tmp" && path != "/Users", "unsafe IDB root");
  for ( const auto *blocked : {"/System", "/Library", "/Applications", "/private/etc", "/private/var/db"} )
    Check(!Within(blocked, path), "system IDB root is not allowed");
#endif
  for ( const auto *blocked : {"/etc", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin",
                              "/lib", "/lib64", "/boot", "/run"} )
    Check(!Within(blocked, path), "system IDB root is not allowed");
  for ( const auto *name : {"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"} )
    if ( const auto *base = std::getenv(name); base && *base == '/' )
      Check(!Within(std::filesystem::path(base).lexically_normal().string(), path), "private IDB root");
  auto fd = AbsoluteDirectory(path);
  const auto info = Info(fd.get());
  Check(info.st_uid == geteuid() && (info.st_mode & 0022) == 0, "IDB directory must be owned and writable only by its user");
  return {std::move(fd), path, full.filename().string()};
}

Fd Open(const Root &root, const std::vector<std::string> &parts, int flags = O_RDONLY)
{
  Fd current = OpenAt(root.fd.get(), ".", O_RDONLY | O_DIRECTORY);
  for ( std::size_t i = 0; i < parts.size(); ++i )
  {
    Check(parts[i] != root.idb, "current IDB is protected");
    current = OpenAt(current.get(), parts[i], i + 1 == parts.size() ? flags : O_RDONLY | O_DIRECTORY);
  }
  return current;
}

void ValidateParent(const Root &root, const std::vector<std::string> &parts, int parent)
{
  auto fresh_root = AbsoluteDirectory(root.path);
  Check(Identity(Info(fresh_root.get()), Info(root.fd.get())), "IDB root changed");
  auto fresh = Open(root, parts, O_RDONLY | O_DIRECTORY);
  Check(Identity(Info(fresh.get()), Info(parent)), "parent directory changed");
}

std::vector<std::string> Names(int fd)
{
  auto copy = OpenAt(fd, ".", O_RDONLY | O_DIRECTORY);
  // fdopendir owns its descriptor; dup preserves the fresh enumeration offset.
  const int duplicated = fcntl(copy.get(), F_DUPFD_CLOEXEC, 0);
  Check(duplicated >= 0, "directory unavailable");
  const auto close_directory = [](DIR *value) { closedir(value); };
  std::unique_ptr<DIR, decltype(close_directory)> dir(fdopendir(duplicated), close_directory);
  if ( !dir ) { close(duplicated); throw std::runtime_error("directory unavailable"); }
  std::vector<std::string> names;
  for ( ;; )
  {
    errno = 0;
    const auto *entry = readdir(dir.get());
    if ( !entry ) { Check(errno == 0, "directory read failed"); break; }
    const std::string name(entry->d_name);
    if ( name == "." || name == ".." ) continue;
    Check(names.size() < MaxEntries, "directory too large");
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());
  return names;
}

class TextValidator final
{
public:
  bool Boundary() const { return remaining_ == 0; }
  void Feed(unsigned char byte)
  {
    if ( remaining_ == 0 )
    {
      if ( byte < 0x80 ) point_ = byte;
      else if ( byte >= 0xc2 && byte <= 0xdf ) { point_ = byte & 31; minimum_ = 0x80; remaining_ = 1; return; }
      else if ( byte >= 0xe0 && byte <= 0xef ) { point_ = byte & 15; minimum_ = 0x800; remaining_ = 2; return; }
      else if ( byte >= 0xf0 && byte <= 0xf4 ) { point_ = byte & 7; minimum_ = 0x10000; remaining_ = 3; return; }
      else throw std::runtime_error("invalid UTF-8 text");
    }
    else
    {
      Check((byte & 0xc0) == 0x80, "invalid UTF-8 text");
      point_ = (point_ << 6) | (byte & 63);
      if ( --remaining_ ) return;
      Check(point_ >= minimum_ && point_ <= 0x10ffff && !(point_ >= 0xd800 && point_ <= 0xdfff), "invalid UTF-8 text");
    }
    Check(!(point_ < 32 && point_ != 9 && point_ != 10 && point_ != 13)
        && !(point_ >= 127 && point_ <= 159), "binary content is not allowed");
  }
  void Finish() const { Check(Boundary(), "incomplete UTF-8 text"); }
private:
  unsigned remaining_ = 0;
  std::uint32_t point_ = 0, minimum_ = 0;
};

template <typename Consumer>
void Stream(int fd, Consumer consumer)
{
  const auto before = Info(fd);
  Check(S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_size >= 0
      && static_cast<std::uint64_t>(before.st_size) <= MaxFileSize, "invalid file");
  std::array<char, 65536> buffer{};
  off_t offset = 0;
  while ( offset < before.st_size )
  {
    const auto count = pread(fd, buffer.data(), std::min<off_t>(buffer.size(), before.st_size - offset), offset);
    if ( count < 0 && errno == EINTR ) continue;
    Check(count > 0, "file read failed");
    consumer(std::string_view(buffer.data(), static_cast<std::size_t>(count)));
    offset += count;
  }
  Check(Unchanged(before, Info(fd)), "file changed during read");
}

std::string Hash(int fd, bool text)
{
  AgentEffectSha256State hash;
  TextValidator validator;
  Stream(fd, [&](std::string_view block) {
    if ( text ) for ( unsigned char byte : block ) validator.Feed(byte);
    hash.Update(block);
  });
  if ( text ) validator.Finish();
  return hash.Final();
}

std::string Page(int fd, std::uint64_t offset, std::uint32_t maximum)
{
  TextValidator validator;
  std::uint64_t position = 0;
  std::size_t complete = 0;
  std::string page;
  Stream(fd, [&](std::string_view block) {
    for ( unsigned char byte : block )
    {
      if ( position == offset ) Check(validator.Boundary(), "offset splits UTF-8");
      validator.Feed(byte);
      if ( position >= offset && position - offset < maximum )
      {
        page.push_back(static_cast<char>(byte));
        if ( validator.Boundary() ) complete = page.size();
      }
      ++position;
    }
  });
  validator.Finish();
  Check(offset <= position, "invalid offset");
  page.resize(complete);
  Check(offset == position || !page.empty(), "page too small for UTF-8 character");
  return page;
}

void Field(AgentEffectSha256State &hash, std::string_view value)
{
  hash.Update(std::to_string(value.size())); hash.Update(":"); hash.Update(value);
}

struct Tree
{
  Fd fd;
  struct stat info{};
  std::string name, hash;
  std::vector<Tree> children;
};

Tree Snapshot(Fd fd, std::string name, AgentEffectSha256State &hash,
    std::size_t &entries, std::uint64_t &bytes, unsigned depth = 0)
{
  Check(depth <= 64 && ++entries <= MaxEntries, "directory tree too large");
  Tree node{std::move(fd), {}, std::move(name), {}, {}};
  node.info = Info(node.fd.get());
  Field(hash, node.name);
  Field(hash, std::to_string(node.info.st_dev));
  Field(hash, std::to_string(node.info.st_ino));
  if ( S_ISDIR(node.info.st_mode) )
  {
    hash.Update("D");
    for ( const auto &child : Names(node.fd.get()) )
    {
      Components(child);
      node.children.push_back(Snapshot(OpenAt(node.fd.get(), child), child, hash, entries, bytes, depth + 1));
    }
  }
  else
  {
    hash.Update("F");
    Check(node.info.st_size >= 0 && static_cast<std::uint64_t>(node.info.st_size) <= MaxTreeBytes - bytes, "directory tree too large");
    bytes += node.info.st_size;
    node.hash = Hash(node.fd.get(), false);
    Field(hash, std::to_string(node.info.st_size));
    Field(hash, node.hash);
  }
  hash.Update("E");
  Check(Unchanged(node.info, Info(node.fd.get())), "directory tree changed");
  return node;
}

AgentFileState State(int fd, Tree *tree = nullptr)
{
  const auto info = Info(fd);
  AgentFileState state{true, S_ISDIR(info.st_mode) ? "directory" : "file", 0, {},
      static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino)};
  if ( S_ISDIR(info.st_mode) )
  {
    AgentEffectSha256State hash;
    std::size_t entries = 0;
    auto snapshot = Snapshot(OpenAt(fd, ".", O_RDONLY | O_DIRECTORY), "", hash, entries, state.size);
    state.sha256 = hash.Final();
    if ( tree ) *tree = std::move(snapshot);
  }
  else { state.size = info.st_size; state.sha256 = Hash(fd, true); }
  return state;
}

bool Same(const AgentFileState &a, const AgentFileState &b)
{
  return a.exists == b.exists && a.type == b.type && a.size == b.size
      && a.sha256 == b.sha256 && a.volume == b.volume && a.file_index == b.file_index;
}

bool Exists(int parent, const std::string &name)
{
  struct stat info{};
  if ( fstatat(parent, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0 ) return true;
  Check(errno == ENOENT, "cannot inspect target");
  return false;
}

void NamedIdentity(int parent, const std::string &name, const struct stat &expected)
{
  struct stat info{};
  Check(fstatat(parent, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0
      && Identity(info, expected) && (S_ISDIR(info.st_mode) || info.st_nlink == 1), "target changed");
}

void DeleteTree(int parent, const std::string &name, Tree &node, bool &changed)
{
  NamedIdentity(parent, name, node.info);
  Check(Unchanged(node.info, Info(node.fd.get())), "tree changed after approval");
  if ( S_ISDIR(node.info.st_mode) )
  {
    for ( auto &child : node.children ) DeleteTree(node.fd.get(), child.name, child, changed);
    Check(Names(node.fd.get()).empty(), "directory changed during deletion");
  }
  else Check(Hash(node.fd.get(), false) == node.hash, "file changed during deletion");
  NamedIdentity(parent, name, node.info);
  Check(unlinkat(parent, name.c_str(), S_ISDIR(node.info.st_mode) ? AT_REMOVEDIR : 0) == 0, "deletion failed");
  changed = true;
}

void ValidateContent(std::string_view mode, std::string_view content)
{
  const bool writes = mode == "overwrite" || mode == "append" || mode == "create_file";
  Check(writes || mode == "create_directory" || mode == "delete_file" || mode == "delete_directory", "invalid mutation mode");
  Check(content.size() <= MaxAgentFileContentBytes && (writes || content.empty()), "invalid mutation content");
  TextValidator validator;
  for ( unsigned char byte : content ) validator.Feed(byte);
  validator.Finish();
}

void Write(int fd, std::string_view content, std::uint64_t offset, bool &changed)
{
  std::size_t written = 0;
  while ( written < content.size() )
  {
    const auto count = pwrite(fd, content.data() + written, content.size() - written, offset + written);
    if ( count < 0 && errno == EINTR ) continue;
    Check(count > 0, "file write failed");
    changed = true;
    written += count;
  }
}
} // namespace

AgentFileService::AgentFileService(IdbPathProvider provider) : idb_path_provider_(std::move(provider)) {}

Json AgentFileService::List(std::string_view path, std::uint32_t limit) const
{
  Check(limit > 0 && limit <= 100, "invalid limit");
  auto root = CurrentRoot(idb_path_provider_);
  auto dir = Open(root, Components(path, true), O_RDONLY | O_DIRECTORY);
  Json items = Json::array();
  std::size_t count = 0;
  for ( const auto &name : Names(dir.get()) )
  {
    try { Components(name); } catch ( ... ) { continue; }
    if ( name == root.idb ) continue;
    struct stat info{};
    Check(fstatat(dir.get(), name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0, "directory changed");
    if ( !S_ISDIR(info.st_mode) && !(S_ISREG(info.st_mode) && info.st_nlink == 1) ) continue;
    if ( count++ < limit ) items.push_back({{"path", std::string(path) + (path.empty() ? "" : "/") + name},
        {"name", name}, {"type", S_ISDIR(info.st_mode) ? "directory" : "file"},
        {"size", S_ISDIR(info.st_mode) ? 0 : info.st_size}});
  }
  return {{"items", std::move(items)}, {"hasMore", count > limit}};
}

Json AgentFileService::Stat(std::string_view path) const
{
  auto root = CurrentRoot(idb_path_provider_);
  const auto parts = Components(path);
  auto fd = Open(root, parts);
  const auto info = Info(fd.get());
  return {{"path", path}, {"name", parts.back()}, {"type", S_ISDIR(info.st_mode) ? "directory" : "file"},
      {"size", S_ISDIR(info.st_mode) ? 0 : info.st_size},
      {"modifiedTimeMs", ModifiedTimeMs(info)},
      {"readOnly", (info.st_mode & 0222) == 0}};
}

Json AgentFileService::Read(std::string_view path, std::uint64_t offset, std::uint32_t max_bytes) const
{
  Check(max_bytes > 0 && max_bytes <= MaxAgentFileContentBytes, "invalid page size");
  auto root = CurrentRoot(idb_path_provider_);
  auto fd = Open(root, Components(path));
  const auto before = Info(fd.get());
  const auto content = Page(fd.get(), offset, max_bytes);
  Check(Unchanged(before, Info(fd.get())), "file changed during read");
  const bool more = offset + content.size() < static_cast<std::uint64_t>(before.st_size);
  return {{"path", path}, {"content", content}, {"bytesRead", content.size()}, {"hasMore", more},
      {"nextOffset", more ? Json(offset + content.size()) : Json(nullptr)}};
}

std::optional<AgentFileMutationPlan> AgentFileService::PrepareMutation(
    std::string_view path, std::string_view mode, std::string_view content) const
{
  try
  {
    ValidateContent(mode, content);
    auto root = CurrentRoot(idb_path_provider_);
    const auto parts = Components(path);
    Check(parts.back() != root.idb, "current IDB is protected");
    const std::vector<std::string> parents(parts.begin(), parts.end() - 1);
    auto parent = Open(root, parents, O_RDONLY | O_DIRECTORY);
    const auto info = Info(parent.get());
    AgentFileMutationPlan plan{std::string(path), std::string(mode), std::string(content), {},
        static_cast<std::uint64_t>(info.st_dev), static_cast<std::uint64_t>(info.st_ino)};
    if ( Exists(parent.get(), parts.back()) )
    {
      Check(mode != "create_file" && mode != "create_directory", "target exists");
      auto target = OpenAt(parent.get(), parts.back());
      Check(S_ISDIR(Info(target.get()).st_mode) == (mode == "delete_directory"), "invalid target type");
      plan.expected = State(target.get());
    }
    else Check(mode != "delete_file" && mode != "delete_directory", "target missing");
    ValidateParent(root, parents, parent.get());
    return plan;
  }
  catch ( ... ) { return std::nullopt; }
}

AgentFileMutationOutcome AgentFileService::ExecuteMutation(const AgentFileMutationPlan &plan) const noexcept
{
  bool changed = false;
  try
  {
    ValidateContent(plan.mode, plan.content);
    auto root = CurrentRoot(idb_path_provider_);
    const auto parts = Components(plan.path);
    Check(parts.back() != root.idb, "current IDB is protected");
    const std::vector<std::string> parents(parts.begin(), parts.end() - 1);
    auto parent = Open(root, parents, O_RDONLY | O_DIRECTORY);
    const auto info = Info(parent.get());
    Check(static_cast<std::uint64_t>(info.st_dev) == plan.parent_volume
        && static_cast<std::uint64_t>(info.st_ino) == plan.parent_file_index, "parent changed after approval");
    ValidateParent(root, parents, parent.get());
    const bool writes = plan.mode == "overwrite" || plan.mode == "append" || plan.mode == "create_file";
    Json result{{"path", plan.path}, {"mode", plan.mode}};
    if ( !plan.expected.exists )
    {
      Check(writes || plan.mode == "create_directory", "invalid absent target");
      if ( plan.mode == "create_directory" )
      {
        Check(mkdirat(parent.get(), parts.back().c_str(), 0700) == 0, "directory creation failed");
        changed = true;
        result["type"] = "directory";
      }
      else
      {
        // O_EXCL also rejects symlinks and pre-existing special files.
        Fd target(openat(parent.get(), parts.back().c_str(),
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600));
        Check(target.get() >= 0, "file creation failed");
        changed = true;
        const auto created = Info(target.get());
        Check(S_ISREG(created.st_mode) && created.st_nlink == 1, "created target changed");
        ValidateParent(root, parents, parent.get());
        Write(target.get(), plan.content, 0, changed);
        NamedIdentity(parent.get(), parts.back(), Info(target.get()));
        Check(fsync(target.get()) == 0, "file flush failed");
      }
    }
    else
    {
      Check(plan.mode != "create_file" && plan.mode != "create_directory", "invalid existing target");
      auto target = OpenAt(parent.get(), parts.back(), writes ? O_RDWR : O_RDONLY);
      Check(flock(target.get(), LOCK_EX | LOCK_NB) == 0, "target is busy");
      Tree tree;
      Check(Same(State(target.get(), &tree), plan.expected), "target changed after approval");
      ValidateParent(root, parents, parent.get());
      NamedIdentity(parent.get(), parts.back(), Info(target.get()));
      if ( plan.mode == "delete_directory" )
      {
        Check(plan.expected.type == "directory", "not a directory");
        DeleteTree(parent.get(), parts.back(), tree, changed);
      }
      else if ( plan.mode == "delete_file" )
      {
        Check(plan.expected.type == "file", "not a file");
        Check(unlinkat(parent.get(), parts.back().c_str(), 0) == 0, "file deletion failed");
        changed = true;
      }
      else
      {
        Check(writes && plan.expected.type == "file", "invalid write target");
        const auto offset = plan.mode == "append" ? plan.expected.size : 0;
        Check(offset + plan.content.size() <= MaxFileSize, "file too large");
        Write(target.get(), plan.content, offset, changed);
        if ( plan.mode == "overwrite" )
        {
          Check(ftruncate(target.get(), plan.content.size()) == 0, "file truncation failed");
          changed = true;
        }
        Check(fsync(target.get()) == 0, "file flush failed");
        NamedIdentity(parent.get(), parts.back(), Info(target.get()));
      }
    }
    ValidateParent(root, parents, parent.get());
    if ( writes ) { result["type"] = "file"; result["bytesWritten"] = plan.content.size(); }
    if ( plan.mode == "delete_file" || plan.mode == "delete_directory" ) result["deleted"] = true;
    return {AgentFileMutationStatus::Success, std::move(result)};
  }
  catch ( ... )
  {
    return {changed ? AgentFileMutationStatus::StateUncertain : AgentFileMutationStatus::Rejected, Json::object()};
  }
}

std::optional<AgentFileScriptSnapshot> AgentFileService::PrepareScript(
    std::string_view path, std::string_view language) const
{
  try
  {
    Check(language == "python" || language == "idc", "invalid script language");
    auto root = CurrentRoot(idb_path_provider_);
    auto fd = Open(root, Components(path));
    const auto info = Info(fd.get());
    Check(info.st_size > 0 && info.st_size <= static_cast<off_t>(MaxAgentScriptBytes), "invalid script size");
    auto source = Page(fd.get(), 0, MaxAgentScriptBytes);
    return AgentFileScriptSnapshot{std::string(path), std::string(language), source, AgentEffectSha256(source)};
  }
  catch ( ... ) { return std::nullopt; }
}
} // namespace ida_agent::ai

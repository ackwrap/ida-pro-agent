#include "ai/agent_file_service.hpp"
#include "ai/agent_effect_digest.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <filesystem>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
using namespace ida_agent::ai;
namespace fs = std::filesystem;

void Require(bool condition, const char *message)
{
  if ( !condition ) throw std::runtime_error(message);
}

void Write(const fs::path &path, const std::string &content)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  output.write(content.data(), static_cast<std::streamsize>(content.size()));
  if ( !output ) throw std::runtime_error("test write failed");
}

std::string Read(const fs::path &path)
{
  std::ifstream input(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input), {});
}

std::string WriteRepeated(
    const fs::path &path,
    std::string_view block,
    std::size_t count)
{
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  AgentEffectSha256State hash;
  for ( std::size_t index = 0; index < count; ++index )
  {
    output.write(block.data(), static_cast<std::streamsize>(block.size()));
    hash.Update(block);
  }
  if ( !output ) throw std::runtime_error("large test write failed");
  return hash.Final();
}

template <typename Operation>
bool Throws(Operation operation)
{
  try { operation(); return false; }
  catch ( const std::exception & ) { return true; }
}

AgentFileMutationOutcome Mutate(
    AgentFileService &service,
    std::string path,
    std::string mode,
    std::string content = {})
{
  const auto plan = service.PrepareMutation(path, mode, content);
  Require(plan.has_value(), "mutation prepare failed");
  return service.ExecuteMutation(*plan);
}

void TestReadOnly(AgentFileService &service, const fs::path &root)
{
  Write(root / "z.txt", "last");
  Write(root / "a.txt", "abc\xE4\xB8\xAD" "def");
  fs::create_directory(root / "sub");
  const auto listed = service.List("", 2);
  Require(listed.at("items").size() == 2 && listed.at("hasMore").get<bool>(),
      "bounded list failed");
  Require(listed.at("items")[0].at("name") == "a.txt"
      && listed.at("items")[1].at("name") == "sub", "list filtering/order changed");
  Require(listed.dump().find(root.string()) == std::string::npos, "list leaked root");
  Require(listed.dump().find("sample.i64") == std::string::npos, "list exposed current IDB");

  const auto stat = service.Stat("a.txt");
  Require(stat.at("path") == "a.txt" && stat.at("type") == "file"
      && stat.at("size") == 9 && stat.contains("modifiedTimeMs"), "stat metadata failed");
  Require(service.Stat("sub").at("type") == "directory", "directory stat type failed");
  const auto first = service.Read("a.txt", 0, 3);
  const auto unicode = service.Read("a.txt", 3, 3);
  Require(first.at("content") == "abc" && first.at("hasMore").get<bool>()
      && first.at("nextOffset") == 3, "first read page failed");
  Require(unicode.at("content") == "\xE4\xB8\xAD" && unicode.at("bytesRead") == 3,
      "UTF-8 page failed");
  Require(Throws([&]() { service.Read("a.txt", 4, 3); }), "split UTF-8 offset accepted");
  Require(Throws([&]() { service.Read("sub", 0, 1); }), "directory read accepted");
  Require(Throws([&]() { service.Read("a.txt", 0,
      static_cast<std::uint32_t>(MaxAgentFileContentBytes + 1)); }), "oversized read accepted");
  Require(Throws([&]() { service.Read("sample.i64", 0, 1); }), "current IDB read accepted");

  std::string boundary(65535, 'a');
  boundary += "\xE4\xB8\xAD";
  boundary += "tail";
  Write(root / "boundary.txt", boundary);
  const auto across = service.Read("boundary.txt", 65534, 4);
  Require(across.at("content") == std::string("a") + "\xE4\xB8\xAD"
      && across.at("bytesRead") == 4, "streaming UTF-8 boundary page failed");

  const std::string block(64 * 1024, 'b');
  const std::string expected_hash = WriteRepeated(root / "stream-large.txt", block, 128);
  const auto small_page = service.Read("stream-large.txt", 7 * 1024 * 1024 + 3, 7);
  Require(small_page.at("content") == "bbbbbbb" && small_page.at("bytesRead") == 7,
      "large-file small page failed");
  const auto large_plan = service.PrepareMutation("stream-large.txt", "append", "x");
  Require(large_plan && large_plan->expected.size == 8ULL * 1024 * 1024
      && large_plan->expected.sha256 == expected_hash,
      "mutation prepare did not stream the large-file hash");
}

void TestMutations(AgentFileService &service, const fs::path &root)
{
  Write(root / "change.txt", "old");
  auto overwrite = service.PrepareMutation("change.txt", "overwrite", "new");
  Require(overwrite && overwrite->expected.exists && overwrite->expected.type == "file"
      && overwrite->expected.size == 3 && overwrite->expected.sha256.size() == 64
      && Read(root / "change.txt") == "old", "prepare state or side-effect mismatch");
  Require(service.ExecuteMutation(*overwrite).status == AgentFileMutationStatus::Success
      && Read(root / "change.txt") == "new", "overwrite failed");
  Require(Mutate(service,"change.txt","append","+").status == AgentFileMutationStatus::Success
      && Read(root / "change.txt") == "new+", "append failed");

  auto create = service.PrepareMutation("created.txt", "create_file", "created");
  Require(create && !fs::exists(root / "created.txt"), "create prepare had a side effect");
  Require(service.ExecuteMutation(*create).status == AgentFileMutationStatus::Success
      && Read(root / "created.txt") == "created", "create file failed");
  auto create_race = service.PrepareMutation("created-race.txt", "create_file", "approved");
  Require(create_race && !create_race->expected.exists, "absent create state missing");
  Write(root / "created-race.txt", "external");
  Require(service.ExecuteMutation(*create_race).status == AgentFileMutationStatus::Rejected
      && Read(root / "created-race.txt") == "external", "create race overwrote a file");
  Require(Mutate(service,"made","create_directory").status == AgentFileMutationStatus::Success
      && fs::is_directory(root / "made"), "create directory failed");
  Require(Mutate(service,"created.txt","delete_file").status == AgentFileMutationStatus::Success
      && !fs::exists(root / "created.txt"), "delete file failed");
  Require(Mutate(service,"made","delete_directory").status == AgentFileMutationStatus::Success
      && !fs::exists(root / "made"), "empty directory deletion failed");

  fs::create_directories(root / "tree" / "sub");
  Write(root / "tree" / "a.txt", "alpha");
  Write(root / "tree" / "sub" / "b.txt", "beta");
  const auto tree = service.PrepareMutation("tree", "delete_directory", "");
  Require(tree && tree->expected.type == "directory" && tree->expected.size == 9
      && tree->expected.sha256.size() == 64, "tree state was not recorded");
  Require(service.ExecuteMutation(*tree).status == AgentFileMutationStatus::Success
      && !fs::exists(root / "tree"), "recursive directory deletion failed");

  fs::create_directories(root / "tree-shape" / "a");
  Write(root / "tree-shape" / "a" / "b", "same");
  const auto tree_shape = service.PrepareMutation("tree-shape", "delete_directory", "");
  Require(tree_shape.has_value(), "tree-shape state was not recorded");
  fs::remove(root / "tree-shape" / "a" / "b");
  Write(root / "tree-shape" / "b", "same");
  Require(service.ExecuteMutation(*tree_shape).status == AgentFileMutationStatus::Rejected
      && fs::exists(root / "tree-shape" / "b"),
      "structurally changed directory tree was deleted");

  fs::create_directories(root / "nested" / "deep");
  Write(root / "nested" / "deep" / "f.txt", "deep");
  const std::string binary("bin\x01\x02\x03");
  Write(root / "nested" / "data.bin", binary);
  Require(Mutate(service, "nested", "delete_directory").status == AgentFileMutationStatus::Success
      && !fs::exists(root / "nested"), "nested directory deletion failed");

  Write(root / "race.txt", "one");
  auto race = service.PrepareMutation("race.txt", "overwrite", "approved");
  Require(race.has_value(), "race prepare failed");
  Write(root / "race.txt", "two");
  Require(service.ExecuteMutation(*race).status == AgentFileMutationStatus::Rejected
      && Read(root / "race.txt") == "two", "changed expected state was written");
  fs::create_directory(root / "empty-race");
  auto directory_race = service.PrepareMutation("empty-race", "delete_directory", "");
  Require(directory_race && directory_race->expected.sha256.size() == 64,
      "directory state was not recorded");
  Write(root / "empty-race" / "child", "x");
  Require(service.ExecuteMutation(*directory_race).status == AgentFileMutationStatus::Rejected
      && fs::exists(root / "empty-race" / "child"), "changed directory was deleted");
  Require(!service.PrepareMutation("large.txt", "overwrite",
      std::string(MaxAgentFileContentBytes + 1, 'x')), "oversized mutation accepted");
  Require(service.PrepareMutation("large.txt", "overwrite",
      std::string(MaxAgentFileContentBytes, '\"')).has_value(),
      "maximum JSON-escaped text mutation was rejected");
  Require(!service.PrepareMutation("nested/missing", "create_directory", ""),
      "missing parent accepted");

  fs::create_directory(root / "guarded");
  Write(root / "guarded" / ".env", "secret");
  Require(!service.PrepareMutation("guarded", "delete_directory", ""),
      "sensitive child was prepared for deletion");
  Require(fs::exists(root / "guarded" / ".env"), "sensitive child was deleted by prepare");

  fs::create_directory(root / "shared-tree");
  Write(root / "shared-tree" / "one.txt", "x");
  const fs::path second = root / "shared-tree" / "two.txt";
  fs::create_hard_link(root / "shared-tree" / "one.txt", second);
  Require(!service.PrepareMutation("shared-tree", "delete_directory", ""),
      "shared-file tree was prepared for deletion");
}

void TestPathAndObjectSafety(AgentFileService &service, const fs::path &root)
{
  const std::vector<std::string> invalid{"C:\\outside", "C:relative", "\\\\server\\share",
#ifdef _WIN32
      "../outside", "sub/../outside", "a.txt:stream", "CON.txt", "CONIN$", "CONOUT$",
      "CLOCK$", "COM1 .txt", "COM\xC2\xB9.txt", "LPT\xC2\xB2.log",
      "wild*", "trail. ",
#else
      "../outside", "sub/../outside", "a.txt:stream", "/etc/passwd", "sub//name",
#endif
      ".git/config"};
  fs::create_directory(root / ".git");
  for ( const std::string &path : invalid )
  {
    Require(Throws([&]() { service.Stat(path); }), "unsafe stat path accepted");
    Require(!service.PrepareMutation(path, "overwrite", "x"), "unsafe mutation path accepted");
  }
  Require(!service.PrepareMutation("sample.i64", "overwrite", "x"), "IDB mutation accepted");
  Require(!service.PrepareMutation("other.id0", "overwrite", "x"), "IDA component mutation accepted");
  Require(!service.PrepareScript("sample.i64", "python"), "IDB script accepted");
  Write(root / "other.id0", "text");
  Require(Throws([&]() { service.Stat("sample.i64"); }), "current IDB stat accepted");
  Require(Throws([&]() { service.Stat("other.id0"); }), "IDA component stat accepted");
  Require(Throws([&]() { service.Read("other.id0", 0, 4); }), "IDA component read accepted");
  Require(!service.PrepareScript("other.id0", "python"), "IDA component script accepted");

  const std::vector<std::string> sensitive_files{".env", ".env.production", ".netrc",
      ".npmrc", ".pypirc", "credentials", "credentials.json", "secrets.dev",
      "client.PEM", "private.key", "identity.pfx", "identity.p12", "vault.kdbx"};
  for ( const std::string &name : sensitive_files )
  {
    Write(root / fs::u8path(name), "sensitive");
    Require(Throws([&]() { service.Stat(name); }), "sensitive file stat accepted");
    Require(Throws([&]() { service.Read(name, 0, 1); }), "sensitive file read accepted");
    Require(!service.PrepareMutation(name, "overwrite", "x"), "sensitive mutation accepted");
    Require(!service.PrepareScript(name, "python"), "sensitive script accepted");
  }
  const std::string filtered = service.List("", 100).dump();
  for ( const std::string &name : sensitive_files )
    Require(filtered.find(name) == std::string::npos, "list exposed a sensitive filename");
  Require(filtered.find("sample.i64") == std::string::npos
      && filtered.find("other.id0") == std::string::npos
      && filtered.find(".git") == std::string::npos,
      "list exposed a protected object");

  Write(root / "linked.txt", "linked");
  const fs::path hard = root / "hard.txt";
  fs::create_hard_link(root / "linked.txt", hard);
  Require(Throws([&]() { service.Stat("linked.txt"); }), "hard-link stat accepted");
  Require(Throws([&]() { service.Read("linked.txt", 0, 6); }), "hard-link read accepted");
  Require(!service.PrepareMutation("linked.txt", "overwrite", "x"), "hard-link mutation accepted");
  Require(!service.PrepareScript("linked.txt", "python"), "hard-link script accepted");

  const fs::path outside = root.parent_path() / (root.filename().wstring() + L"-outside");
  fs::create_directory(outside);
  Write(outside / "escape.txt", "escape");
  const fs::path link = root / "junction";
#ifdef _WIN32
  const DWORD flags = SYMBOLIC_LINK_FLAG_DIRECTORY | 0x2;
  if ( CreateSymbolicLinkW(link.c_str(), outside.c_str(), flags) )
  {
    Require(Throws([&]() { service.Stat("junction/escape.txt"); }), "reparse escape accepted");
    RemoveDirectoryW(link.c_str());
  }
#else
  fs::create_directory_symlink(outside, link);
  Require(Throws([&]() { service.Stat("junction/escape.txt"); }), "symlink escape accepted");
  Require(!service.PrepareMutation("junction/escape.txt", "overwrite", "x"), "symlink write accepted");
  fs::remove(link);
  fs::create_symlink(outside / "escape.txt", root / "symlink.txt");
  Require(!service.PrepareMutation("symlink.txt", "overwrite", "x"), "symlink target accepted");
  Require(mkfifo((root / "fifo").c_str(), 0600) == 0, "FIFO setup failed");
  Require(Throws([&]() { service.Read("fifo", 0, 1); }), "FIFO read accepted");
  Require(!service.PrepareMutation("fifo", "overwrite", "x"), "FIFO write accepted");
  fs::create_directory(root / "replaced-parent");
  auto stale = service.PrepareMutation("replaced-parent/child.txt", "create_file", "x");
  Require(stale.has_value(), "parent snapshot missing");
  fs::rename(root / "replaced-parent", root / "old-parent");
  fs::create_directory(root / "replaced-parent");
  Require(service.ExecuteMutation(*stale).status == AgentFileMutationStatus::Rejected
      && !fs::exists(root / "replaced-parent/child.txt"), "replaced parent accepted");
  Write(root / "Case.txt", "upper");
  Write(root / "case.txt", "lower");
  Require(service.Read("Case.txt", 0, 5).at("content") ==
          (fs::equivalent(root / "Case.txt", root / "case.txt") ? "lower" : "upper")
      && service.Read("case.txt", 0, 5).at("content") == "lower", "case-sensitive paths collapsed");
#endif
  fs::remove_all(outside);
}

void TestScriptsAndNoIdb(AgentFileService &service, const fs::path &root)
{
  Write(root / "analysis.py", "import ida_funcs\nprint(ida_funcs.get_func_qty())\n");
  const auto script = service.PrepareScript("analysis.py", "python");
  Require(script && script->path == "analysis.py" && script->source.find("ida_funcs") != std::string::npos
      && script->sha256.size() == 64, "script snapshot failed");
  Require(!service.PrepareScript("analysis.py", "ruby"), "unknown script language accepted");
  auto no_idb = AgentFileService::ForTesting("");
  Require(Throws([&]() { no_idb.List("", 1); }), "missing IDB was accepted");
#ifdef _WIN32
  std::vector<wchar_t> windows(MAX_PATH, L'\0');
  const UINT count = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
  Require(count > 0 && count < windows.size(), "Windows directory unavailable");
  fs::path sensitive(std::wstring(windows.data(), count));
#else
  fs::path sensitive("/etc");
#endif
  auto sensitive_root = AgentFileService::ForTesting((sensitive / "blocked.i64").u8string());
  Require(Throws([&]() { sensitive_root.List("", 1); }), "sensitive IDB root was accepted");

  const fs::path nested = root / "nested-sensitive" / ".git" / "project";
  fs::create_directories(nested);
  Write(nested / "nested.i64", "idb");
  auto nested_sensitive = AgentFileService::ForTesting((nested / "nested.i64").u8string());
  Require(Throws([&]() { nested_sensitive.List("", 1); })
      && Throws([&]() { nested_sensitive.Stat("x.txt"); })
      && Throws([&]() { nested_sensitive.Read("x.txt", 0, 1); })
      && !nested_sensitive.PrepareMutation("x.txt", "overwrite", "x")
      && !nested_sensitive.PrepareScript("x.txt", "python"),
      "a file tool accepted a sensitive component in the normalized IDB root");
}

void TestIncrementalDigest()
{
  AgentEffectSha256State state;
  state.Update("a");
  state.Update("bc");
  Require(state.Final() == "ba7816bf8f01cfea414140de5dae2223"
      "b00361a396177a9cb410ff61f20015ad", "incremental SHA-256 mismatch");
}

} // namespace

int main()
{
  fs::path root;
  try
  {
#ifdef _WIN32
    const auto pid = GetCurrentProcessId();
#else
    const auto pid = getpid();
#endif
    root = fs::current_path() / ("ida-agent-file-test-" + std::to_string(pid));
    fs::remove_all(root);
    fs::create_directory(root);
    Write(root / "sample.i64", "idb");
    AgentFileService service = AgentFileService::ForTesting((root / "sample.i64").u8string());
    TestIncrementalDigest();
    TestReadOnly(service, root);
    TestMutations(service, root);
    TestPathAndObjectSafety(service, root);
    TestScriptsAndNoIdb(service, root);
    fs::remove_all(root);
    return 0;
  }
  catch ( const std::exception &error )
  {
    std::fprintf(stderr, "%s\n", error.what());
    if ( !root.empty() ) fs::remove_all(root);
    return 1;
  }
}

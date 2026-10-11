#include "ai/chat_code_tokens.hpp"
#include "ai/chat_code_fences.hpp"
#include <stdexcept>

namespace
{
using namespace ida_agent::ai;
using Language = ChatCodeLanguage;
using Kind = ChatCodeTokenKind;

void Require(bool condition, const char *message)
{
  if ( !condition )
    throw std::runtime_error(message);
}

bool Colored(const std::vector<ChatCodeToken> &tokens, std::size_t index, Kind kind)
{
  for ( const auto &token : tokens )
    if ( index >= token.start && index < token.start + token.length )
      return token.kind == kind;
  return false;
}

void Check(std::u16string_view line, std::u16string_view needle, Kind kind, Language language)
{
  ChatCodeState state;
  const auto tokens = TokenizeChatCodeLine(line, language, state);
  const auto index = line.find(needle);
  Require(index != line.npos && Colored(tokens, index, kind), "code token classification failed");
}
} // namespace

int main()
{
  const std::string fence(3, char(96));
  const auto adjacent = PrepareChatCodeMarkdown(fence + "cpp\n/* isolated\n" + fence
      + "\n\n" + fence + "cpp\nreturn 1;\n" + fence + "\n");
  Require(adjacent.languages.size() == 2 && adjacent.languages[0] == "cpp"
      && adjacent.languages[1] == "cpp", "adjacent identical-language fences lost identity");
  Require(adjacent.text.find(adjacent.marker_prefix + "1") != std::string::npos
      && adjacent.text.find(adjacent.marker_prefix + "2") != std::string::npos,
      "fence identity markers missing");
  Require(adjacent.text.find("/* isolated\n") != std::string::npos
      && adjacent.text.find("return 1;\n") != std::string::npos, "code body changed");
  const auto quoted = PrepareChatCodeMarkdown("> " + fence + "py\n> pass\n> " + fence + "\n");
  Require(quoted.languages.size() == 1 && quoted.languages[0] == "py", "quoted fence missed");
  const auto listed = PrepareChatCodeMarkdown("- " + fence + "json\n  {}\n  " + fence + "\n");
  Require(listed.languages.size() == 1, "list fence missed");
  const std::string indented = "    " + fence + "cpp\n    raw literal\n";
  Require(PrepareChatCodeMarkdown(indented).text == indented, "indented code literal changed");
  const auto nested_literal = PrepareChatCodeMarkdown(fence + "cpp\n> " + fence
      + "\nint same;\n" + fence + "\n" + fence + "py\npass\n" + fence);
  Require(nested_literal.languages.size() == 2, "quoted literal closed an outer fence");
  const auto tilde = PrepareChatCodeMarkdown("~~~~C++\r\nint unchanged;\r\n~~~~\r\n");
  Require(tilde.languages.size() == 1 && tilde.languages[0] == "C++"
      && tilde.text.find("int unchanged;\r\n") != std::string::npos, "tilde/CRLF fence changed");
  const auto collision = PrepareChatCodeMarkdown(fence + "ida_agent_fence_0_1\nx\n" + fence);
  Require(collision.marker_prefix != "ida_agent_fence_0_", "private marker collided with input");
  Require(ResolveChatCodeLanguage(" C++ extra", u"") == Language::Cpp, "C++ alias failed");
  Require(ResolveChatCodeLanguage("IDAPython", u"") == Language::Python, "Python alias failed");
  Require(ResolveChatCodeLanguage("aarch64", u"") == Language::Assembly, "ASM alias failed");
  Require(ResolveChatCodeLanguage("JSON", u"") == Language::Json, "JSON alias failed");
  Require(ResolveChatCodeLanguage("rust", u"return 1;") == Language::Plain, "unknown language guessed");
  Require(ResolveChatCodeLanguage("text", u"int x;") == Language::Plain, "explicit plain text guessed");
  Require(ResolveChatCodeLanguage("", u"def inspect(ea):\n    return ea") == Language::Python,
      "unlabelled Python failed");
  Require(ResolveChatCodeLanguage("", u"loc_40:\n    MOV RAX, 0x40") == Language::Assembly,
      "unlabelled ASM failed");
  Require(ResolveChatCodeLanguage("", u"{ \"address\" : 42 }") == Language::Json,
      "unlabelled JSON with spaces failed");
  Require(ResolveChatCodeLanguage("", u"__int64 check() { return 0; }") == Language::Cpp,
      "unlabelled pseudocode failed");

  Check(u"__int64 __fastcall inspect(int value) { return 0x401000; }", u"__int64", Kind::Type, Language::Cpp);
  Check(u"__int64 __fastcall inspect(int value) { return 0x401000; }", u"__fastcall", Kind::Keyword, Language::Cpp);
  Check(u"__int64 inspect() { return 0x401000; }", u"inspect", Kind::Function, Language::Cpp);
  Check(u"return 0x401000 + 1.25e-3;", u"0x401000", Kind::Number, Language::Cpp);
  Check(u"return 0x401000 + 1.25e-3;", u"1.25e-3", Kind::Number, Language::Cpp);
  Check(u"  #include <stdint.h>", u"#include", Kind::Directive, Language::Cpp);
  Check(u"const char *s = \"return 42; // data\"; // real", u"return", Kind::String, Language::Cpp);
  Check(u"int returning = 1;", u"int", Kind::Type, Language::Cpp);
  ChatCodeState state;
  const auto boundary = TokenizeChatCodeLine(u"int returning = 1;", Language::Cpp, state);
  Require(!Colored(boundary, 4, Kind::Keyword), "keyword matched part of identifier");

  state = {};
  TokenizeChatCodeLine(u"/* int value", Language::Cpp, state);
  Require(state.mode == ChatCodeState::Mode::Comment, "multiline comment state missing");
  auto tokens = TokenizeChatCodeLine(u"still comment */ return 42;", Language::Cpp, state);
  Require(Colored(tokens, 0, Kind::Comment) && Colored(tokens, 17, Kind::Keyword),
      "comment terminator swallowed following code");
  Require(state.mode == ChatCodeState::Mode::Normal, "closed comment state leaked");
  state = {};
  TokenizeChatCodeLine(u"auto s = R\"tag(return // still string", Language::Cpp, state);
  Require(state.mode == ChatCodeState::Mode::String, "raw string state missing");
  tokens = TokenizeChatCodeLine(u"/* text */ )tag\"; return 0;", Language::Cpp, state);
  Require(Colored(tokens, 0, Kind::String) && Colored(tokens, 18, Kind::Keyword),
      "raw string delimiter swallowed following code");

  Check(u"def inspect(ea): # return 1", u"def", Kind::Keyword, Language::Python);
  Check(u"def inspect(ea): # return 1", u"inspect", Kind::Function, Language::Python);
  Check(u"def inspect(ea): # return 1", u"return", Kind::Comment, Language::Python);
  state = {};
  TokenizeChatCodeLine(u"doc = \"\"\"return 1", Language::Python, state);
  tokens = TokenizeChatCodeLine(u"# doc\"\"\"; return 2", Language::Python, state);
  Require(Colored(tokens, 0, Kind::String) && Colored(tokens, 10, Kind::Keyword),
      "Python triple string boundary failed");
  state = {};
  TokenizeChatCodeLine(u"\"unfinished\\\\", Language::Python, state);
  Require(state.mode == ChatCodeState::Mode::Normal, "even trailing backslashes leaked string state");

  Check(u"MOV RAX, 0x401000 ; return value", u"MOV", Kind::Keyword, Language::Assembly);
  Check(u"MOV RAX, 0x401000 ; return value", u"RAX", Kind::Type, Language::Assembly);
  Check(u"MOV RAX, 0x401000 ; return value", u"0x401000", Kind::Number, Language::Assembly);
  Check(u"MOV RAX, 0x401000 ; return value", u"return", Kind::Comment, Language::Assembly);
  Check(u"ldr x19, [x20, #0x10]", u"x19", Kind::Type, Language::Assembly);
  Check(u"mov r12d, 42", u"r12d", Kind::Type, Language::Assembly);
  Check(u"loc_4010: ret", u"loc_4010", Kind::Function, Language::Assembly);

  Check(u"{\"address\": 42, \"name\": \"return\", \"ok\": true}", u"address", Kind::Property, Language::Json);
  Check(u"{\"address\": 42, \"name\": \"return\", \"ok\": true}", u"return", Kind::String, Language::Json);
  Check(u"{\"address\": 42, \"name\": \"return\", \"ok\": true}", u"true", Kind::Keyword, Language::Json);
  const std::u16string unicode = u"const char *s = \"\u4f60\U0001f916\"; return 42;";
  state = {};
  tokens = TokenizeChatCodeLine(unicode, Language::Cpp, state);
  Require(Colored(tokens, unicode.find(u"return"), Kind::Keyword)
      && Colored(tokens, unicode.find(u"42"), Kind::Number), "UTF-16 token positions shifted");

  std::u16string dense;
  for ( int index = 0; index < 1000; ++index )
    dense += u"return ";
  dense += u"/* open";
  state = {};
  tokens = TokenizeChatCodeLine(dense, Language::Cpp, state, 999999);
  Require(tokens.size() == MaxChatCodeLineSpans, "per-line span cap failed");
  Require(state.mode == ChatCodeState::Mode::Comment, "span cap discarded lexer state");
  tokens = TokenizeChatCodeLine(u"closed */ return 1;", Language::Cpp, state, 0);
  Require(tokens.empty() && state.mode == ChatCodeState::Mode::Normal,
      "zero span budget discarded lexer state");
  state = {};
  Require(TokenizeChatCodeLine(u"return 42;", Language::Plain, state).empty(),
      "unsupported explicit language highlighted");
  for ( int value = 0; value < 512; ++value )
  {
    std::u16string input = unicode;
    input += static_cast<char16_t>(value);
    input += u"/*\"123";
    state = {};
    tokens = TokenizeChatCodeLine(input, Language::Cpp, state, 12);
    std::size_t end = 0;
    for ( const auto &token : tokens )
    {
      Require(token.start >= end && token.length > 0
          && token.start + token.length <= input.size(), "invalid or overlapping token span");
      end = token.start + token.length;
    }
    Require(tokens.size() <= 12, "caller span budget failed");
  }
  return 0;
}

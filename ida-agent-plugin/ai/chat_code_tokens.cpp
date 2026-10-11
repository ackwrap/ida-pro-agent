#include "ai/chat_code_tokens.hpp"
#include <algorithm>

namespace ida_agent::ai
{
namespace
{
using Kind = ChatCodeTokenKind;
using Language = ChatCodeLanguage;
using Mode = ChatCodeState::Mode;

bool Space(char16_t ch) { return ch == u' ' || ch == u'\t' || ch == u'\r' || ch == u'\n'; }
bool Digit(char16_t ch) { return ch >= u'0' && ch <= u'9'; }
bool WordStart(char16_t ch)
{
  return (ch >= u'a' && ch <= u'z') || (ch >= u'A' && ch <= u'Z') || ch == u'_' || ch >= 0x80;
}
bool Word(char16_t ch) { return WordStart(ch) || Digit(ch); }

std::u16string Lower(std::u16string_view text)
{
  std::u16string result(text);
  for ( char16_t &ch : result )
    if ( ch >= u'A' && ch <= u'Z' )
      ch = static_cast<char16_t>(ch + u'a' - u'A');
  return result;
}

bool Starts(std::u16string_view text, std::u16string_view prefix)
{
  return text.substr(0, prefix.size()) == prefix;
}

bool Listed(std::u16string_view word, std::u16string_view list)
{
  if ( word.empty() )
    return false;
  for ( auto pos = list.find(word); pos != list.npos; pos = list.find(word, pos + 1) )
    if ( (pos == 0 || list[pos - 1] == u' ')
        && (pos + word.size() == list.size() || list[pos + word.size()] == u' ') )
      return true;
  return false;
}

constexpr std::u16string_view CppKeywords =
    u"alignas alignof asm auto break case catch class const constexpr consteval constinit "
    u"continue co_await co_return co_yield decltype default delete do else enum explicit extern "
    u"false for friend goto if inline mutable namespace new noexcept nullptr operator private "
    u"protected public register reinterpret_cast return sizeof static static_assert static_cast "
    u"struct switch template this thread_local throw true try typedef typeid typename union using "
    u"virtual volatile while dynamic_cast const_cast __asm __fastcall __stdcall __cdecl";
constexpr std::u16string_view CppTypes =
    u"bool char char8_t char16_t char32_t double float int long short signed unsigned void wchar_t "
    u"size_t ssize_t ptrdiff_t int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t "
    u"__int8 __int16 __int32 __int64 _BYTE _WORD _DWORD _QWORD _OWORD";
constexpr std::u16string_view PythonKeywords =
    u"False None True and as assert async await break class continue def del elif else except "
    u"finally for from global if import in is lambda nonlocal not or pass raise return try while "
    u"with yield match case";
constexpr std::u16string_view PythonTypes =
    u"bool bytes bytearray dict float frozenset int list object set str tuple type";
constexpr std::u16string_view Instructions =
    u"adc add adds adrp adr and ands asr b bl blr br cbnz cbz call clz cmp cmn csel csinc "
    u"dec div eor fadd fdiv fld fmul fstp fsub hlt imul inc int jmp ja jae jb jbe je jg jge "
    u"jl jle jne jnz jz lea ldar ldp ldr ldrb ldrh ldrsw lsl lsr mov movabs movk movn "
    u"movs movsx movsxd movw movz movzx mul neg nop not or orr pop push ret retn rol ror "
    u"sal sar sbb shl shr stp str strb strh sub subs svc tbnz tbz test tst udiv xor";
constexpr std::u16string_view Registers =
    u"al ah ax eax rax bl bh bx ebx rbx cl ch cx ecx rcx dl dh dx edx rdx si esi rsi "
    u"di edi rdi bp ebp rbp sp esp rsp ip eip rip pc lr fp xzr wzr cpsr nzcv cs ds es fs gs ss";

bool IsRegister(std::u16string_view word)
{
  if ( Listed(word, Registers) )
    return true;
  std::size_t prefix = 0;
  if ( word.size() > 1 && (word[0] == u'r' || word[0] == u'x' || word[0] == u'w'
      || word[0] == u'v' || word[0] == u'd' || word[0] == u's' || word[0] == u'q') )
    prefix = 1;
  else if ( Starts(word, u"xmm") || Starts(word, u"ymm") || Starts(word, u"zmm") )
    prefix = 3;
  if ( prefix == 0 || prefix == word.size() )
    return false;
  unsigned value = 0;
  std::size_t index = prefix;
  while ( index < word.size() && Digit(word[index]) )
  {
    value = value * 10 + static_cast<unsigned>(word[index++] - u'0');
    if ( value > 31 )
      return false;
  }
  if ( index == prefix )
    return false;
  return index == word.size() || (word[0] == u'r' && index + 1 == word.size()
      && (word[index] == u'd' || word[index] == u'w' || word[index] == u'b'));
}

std::size_t SkipSpace(std::u16string_view line, std::size_t index)
{
  while ( index < line.size() && Space(line[index]) )
    ++index;
  return index;
}

std::size_t ConsumeQuoted(std::u16string_view line, std::size_t index, ChatCodeState &state)
{
  while ( index < line.size() )
  {
    if ( state.escapes && line[index] == u'\\' )
    {
      index += (std::min)(std::size_t(2), line.size() - index);
      continue;
    }
    if ( line.substr(index, state.terminator.size()) == state.terminator )
    {
      index += state.terminator.size();
      state = {};
      return index;
    }
    ++index;
  }
  if ( !state.multiline )
  {
    std::size_t backslashes = 0;
    for ( auto end = line.size(); end > 0 && line[end - 1] == u'\\'; --end )
      ++backslashes;
    if ( backslashes % 2 == 0 )
      state = {};
  }
  return index;
}

bool OpenRawString(std::u16string_view line, std::size_t &index, ChatCodeState &state)
{
  for ( const auto prefix : {u"R\"", u"u8R\"", u"uR\"", u"UR\"", u"LR\""} )
  {
    const std::u16string_view marker(prefix);
    if ( line.substr(index, marker.size()) != marker )
      continue;
    const auto start = index + marker.size();
    auto end = start;
    while ( end < line.size() && end - start <= 16 && line[end] != u'('
        && !Space(line[end]) && line[end] != u'\\' && line[end] != u')' )
      ++end;
    if ( end == line.size() || end - start > 16 || line[end] != u'(' )
      return false;
    state.mode = Mode::String;
    state.terminator = u")" + std::u16string(line.substr(start, end - start)) + u"\"";
    state.escapes = false;
    state.multiline = true;
    index = end + 1;
    return true;
  }
  return false;
}
} // namespace

ChatCodeLanguage ResolveChatCodeLanguage(std::string_view hint, std::u16string_view code)
{
  std::string name;
  for ( const char ch : hint )
  {
    if ( ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' )
    {
      if ( !name.empty() )
        break;
      continue;
    }
    name.push_back(ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + 'a' - 'A') : ch);
  }
  if ( name == "c" || name == "cpp" || name == "c++" || name == "cxx"
      || name == "h" || name == "hpp" || name == "pseudocode" )
    return Language::Cpp;
  if ( name == "py" || name == "python" || name == "python3" || name == "idapython" )
    return Language::Python;
  if ( name == "asm" || name == "assembly" || name == "nasm" || name == "x86"
      || name == "x86_64" || name == "x64" || name == "arm" || name == "arm64"
      || name == "aarch64" )
    return Language::Assembly;
  if ( name == "json" )
    return Language::Json;
  if ( !name.empty() )
    return Language::Plain;
  code = code.substr(0, 4096);
  code.remove_prefix(SkipSpace(code, 0));
  if ( !code.empty() && (code.front() == u'{' || code.front() == u'[') )
    for ( auto quote = code.find(u'"'); quote != code.npos; quote = code.find(u'"', quote + 1) )
    {
      const auto next = SkipSpace(code, quote + 1);
      if ( next < code.size() && code[next] == u':' )
        return Language::Json;
    }
  for ( std::size_t start = 0; start < code.size(); )
  {
    const auto end = code.find(u'\n', start);
    const auto line = code.substr(start, end == code.npos ? code.size() - start : end - start);
    const auto first = SkipSpace(line, 0);
    const auto body = line.substr(first);
    if ( Starts(body, u"def ") || Starts(body, u"async def ") || Starts(body, u"from ")
        || Starts(body, u"import ") || Starts(body, u"#!/usr/bin/python") )
      return Language::Python;
    auto last = first;
    while ( last < line.size() && Word(line[last]) )
      ++last;
    if ( last > first && (last == line.size() || Space(line[last]))
        && Listed(Lower(line.substr(first, last - first)), Instructions) )
      return Language::Assembly;
    if ( end == code.npos )
      break;
    start = end + 1;
  }
  return Language::Cpp;
}

std::vector<ChatCodeToken> TokenizeChatCodeLine(std::u16string_view line,
    ChatCodeLanguage language, ChatCodeState &state, std::size_t span_budget)
{
  std::vector<ChatCodeToken> result;
  span_budget = (std::min)(span_budget, MaxChatCodeLineSpans);
  if ( language == Language::Plain )
  {
    state = {};
    return result;
  }
  const auto add = [&](std::size_t start, std::size_t end, Kind kind)
  {
    if ( end > start && result.size() < span_budget )
      result.push_back({start, end - start, kind});
  };
  for ( std::size_t index = 0; index < line.size(); )
  {
    const auto start = index;
    if ( state.mode != Mode::Normal )
    {
      const auto kind = state.mode == Mode::Comment ? Kind::Comment : Kind::String;
      index = ConsumeQuoted(line, index, state);
      add(start, index, kind);
      continue;
    }
    if ( Space(line[index]) )
    {
      ++index;
      continue;
    }
    const auto tail = line.substr(index);
    const bool slash_comments = language == Language::Cpp || language == Language::Assembly;
    if ( (slash_comments && Starts(tail, u"//"))
        || (language == Language::Python && line[index] == u'#')
        || (language == Language::Assembly && (line[index] == u';' || line[index] == u'@')) )
    {
      add(start, line.size(), Kind::Comment);
      break;
    }
    if ( slash_comments && Starts(tail, u"/*") )
    {
      state.mode = Mode::Comment;
      state.terminator = u"*/";
      state.multiline = true;
      state.escapes = false;
      index = ConsumeQuoted(line, index + 2, state);
      add(start, index, Kind::Comment);
      continue;
    }
    if ( language == Language::Cpp && OpenRawString(line, index, state) )
    {
      index = ConsumeQuoted(line, index, state);
      add(start, index, Kind::String);
      continue;
    }
    if ( line[index] == u'"' || (language != Language::Json && line[index] == u'\'') )
    {
      const auto quote = line[index++];
      state.mode = Mode::String;
      state.terminator.assign(1, quote);
      state.escapes = true;
      state.multiline = false;
      if ( language == Language::Python && index + 1 < line.size()
          && line[index] == quote && line[index + 1] == quote )
      {
        state.terminator.assign(3, quote);
        state.multiline = true;
        index += 2;
      }
      index = ConsumeQuoted(line, index, state);
      add(start, index, language == Language::Json && SkipSpace(line, index) < line.size()
          && line[SkipSpace(line, index)] == u':' ? Kind::Property : Kind::String);
      continue;
    }
    if ( language == Language::Cpp && line[index] == u'#' && start == SkipSpace(line, 0) )
    {
      index = SkipSpace(line, index + 1);
      while ( index < line.size() && Word(line[index]) )
        ++index;
      add(start, index, Kind::Directive);
      continue;
    }
    if ( Digit(line[index]) || (line[index] == u'.' && index + 1 < line.size() && Digit(line[index + 1])) )
    {
      ++index;
      while ( index < line.size() )
      {
        const auto ch = line[index];
        if ( Word(ch) || ch == u'.' || ch == u'\''
            || ((ch == u'+' || ch == u'-') && Listed(line.substr(index - 1, 1), u"e E p P")) )
          ++index;
        else
          break;
      }
      add(start, index, Kind::Number);
      continue;
    }
    if ( WordStart(line[index]) )
    {
      while ( index < line.size() && Word(line[index]) )
        ++index;
      const auto word = line.substr(start, index - start);
      const auto next = SkipSpace(line, index);
      if ( language == Language::Cpp && Listed(word, CppTypes) )
        add(start, index, Kind::Type);
      else if ( (language == Language::Cpp && Listed(word, CppKeywords))
          || (language == Language::Python && Listed(word, PythonKeywords))
          || (language == Language::Json && Listed(word, u"true false null"))
          || (language == Language::Assembly && Listed(Lower(word), Instructions)) )
        add(start, index, Kind::Keyword);
      else if ( language == Language::Python && Listed(word, PythonTypes) )
        add(start, index, Kind::Type);
      else if ( language == Language::Assembly && IsRegister(Lower(word)) )
        add(start, index, Kind::Type);
      else if ( language != Language::Json && next < line.size()
          && (line[next] == u'(' || (language == Language::Assembly && line[next] == u':')) )
        add(start, index, Kind::Function);
      continue;
    }
    ++index;
  }
  return result;
}
} // namespace ida_agent::ai

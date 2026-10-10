#include "script_service.hpp"

#include "inventory_text.hpp"

#include <ida.hpp>
#include <expr.hpp>
#include <pro.h>

#include <exception>
#include <string>
#include <utility>

namespace ida_agent::services
{
namespace
{
constexpr std::size_t MaxScriptBytes = 32 * 1024;
constexpr std::size_t MaxStreamBytes = 32 * 1024;

std::string PythonWrapper(std::string_view code)
{
  const std::string source = nlohmann::json(std::string(code)).dump();
  return
      "def __ida_agent_run():\n"
      "    import contextlib as __ctx, traceback as __tb\n"
      "    class __Writer:\n"
      "        def __init__(self, limit):\n"
      "            self.limit, self.parts, self.size, self.original = limit, [], 0, 0\n"
      "        def write(self, value):\n"
      "            text = str(value)\n"
      "            data = text.encode('utf-8', 'replace')\n"
      "            self.original += len(data)\n"
      "            if self.size < self.limit:\n"
      "                part = data[:self.limit - self.size]\n"
      "                self.parts.append(part.decode('utf-8', 'ignore'))\n"
      "                self.size += len(part)\n"
      "            return len(text)\n"
      "        def flush(self):\n"
      "            pass\n"
      "        def value(self):\n"
      "            return ''.join(self.parts)\n"
      "    __out, __err, __ok = __Writer(" + std::to_string(MaxStreamBytes)
      + "), __Writer(" + std::to_string(MaxStreamBytes) + "), True\n"
      "    try:\n"
      "        with __ctx.redirect_stdout(__out), __ctx.redirect_stderr(__err):\n"
      "            exec(" + source + ", globals(), globals())\n"
      "    except BaseException:\n"
      "        __ok = False\n"
      "        __tb.print_exc(file=__err)\n"
      "    return (__ok, __out.value(), __err.value(), "
      "__out.original + __err.original, __out.original > __out.limit or __err.original > __err.limit)\n"
      "__ida_agent_result = __ida_agent_run()\n"
      "del __ida_agent_run\n";
}

bool EvalPythonString(
    const extlang_object_t &python,
    const char *expression,
    std::string *result,
    qstring *error)
{
  idc_value_t value;
  if ( !python->eval_expr(&value, BADADDR, expression, error) || value.vtype != VT_STR )
    return false;
  *result = value.c_str();
  return true;
}

ScriptExecutionOutcome ExecutePython(std::string_view code)
{
  const extlang_object_t python = find_extlang_by_name("Python");
  if ( !python || python->eval_snippet == nullptr || python->eval_expr == nullptr )
    return {ScriptStatus::Unavailable, std::nullopt};

  qstring error;
  const std::string wrapper = PythonWrapper(code);
  if ( !python->eval_snippet(wrapper.c_str(), &error) )
    return {ScriptStatus::Failed, std::nullopt};

  std::string success;
  std::string stdout_text;
  std::string stderr_text;
  std::string original_size;
  std::string truncated;
  const bool decoded =
      EvalPythonString(python, "str(int(__ida_agent_result[0]))", &success, &error)
      && EvalPythonString(python, "__ida_agent_result[1]", &stdout_text, &error)
      && EvalPythonString(python, "__ida_agent_result[2]", &stderr_text, &error)
      && EvalPythonString(python, "str(__ida_agent_result[3])", &original_size, &error)
      && EvalPythonString(python, "str(int(__ida_agent_result[4]))", &truncated, &error);
  qstring cleanup_error;
  python->eval_snippet("globals().pop('__ida_agent_result', None)", &cleanup_error);
  if ( !decoded )
    return {ScriptStatus::Failed, std::nullopt};

  std::uint64_t original = 0;
  try
  {
    original = std::stoull(original_size);
  }
  catch ( const std::exception & )
  {
    return {ScriptStatus::Failed, std::nullopt};
  }
  return {
      ScriptStatus::Success,
      ScriptExecution{
          "python",
          success == "1",
          std::nullopt,
          std::move(stdout_text),
          std::move(stderr_text),
          truncated == "1",
          original,
      },
  };
}

ScriptExecutionOutcome ExecuteIdc(std::string_view code)
{
  idc_value_t value;
  qstring error;
  if ( !eval_idc_snippet(&value, std::string(code).c_str(), &error) )
  {
    const std::string full_error = error.c_str();
    return {
        ScriptStatus::Success,
        ScriptExecution{
            "idc",
            false,
            std::nullopt,
            {},
            TruncateUtf8Bytes(full_error, MaxStreamBytes),
            full_error.size() > MaxStreamBytes,
            full_error.size(),
        },
    };
  }
  qstring printed;
  print_idcv(&printed, value);
  const std::string full_result = printed.c_str();
  return {
      ScriptStatus::Success,
      ScriptExecution{
          "idc",
          true,
          TruncateUtf8Bytes(full_result, MaxStreamBytes),
          {},
          {},
          full_result.size() > MaxStreamBytes,
          full_result.size(),
      },
  };
}
} // namespace

ScriptExecutionOutcome ScriptService::Execute(std::string_view language, std::string_view code) const
{
  if ( code.empty() || code.size() > MaxScriptBytes || code.find('\0') != std::string_view::npos
    || !is_valid_utf8(std::string(code).c_str()) )
    return {ScriptStatus::InvalidArgument, std::nullopt};
  if ( language == "python" )
    return ExecutePython(code);
  if ( language == "idc" )
    return ExecuteIdc(code);
  return {ScriptStatus::InvalidArgument, std::nullopt};
}

nlohmann::json ToJson(const ScriptExecution &result)
{
  return {
      {"language", result.language},
      {"success", result.success},
      {"result", result.result ? nlohmann::json(*result.result) : nlohmann::json(nullptr)},
      {"stdout", result.stdout_text},
      {"stderr", result.stderr_text},
      {"truncated", result.truncated},
      {"originalSize", result.original_size},
  };
}
} // namespace ida_agent::services

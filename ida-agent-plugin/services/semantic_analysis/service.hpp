#pragma once
#include "model.hpp"
#include "callers.hpp"
#include "../query_result.hpp"
namespace ida_agent::services
{
class SemanticAnalysisService
{
public:
  void SetDecompilerAvailable(bool available) noexcept { decompiler_available_ = available; }
  // All SDK access takes place through IdaExecutor.
  QueryResult AnalyzeArgument(const semantic::Request &request, bool guards) const;
  QueryResult TraceArgumentCallers(const semantic::CallersRequest &request) const;
private:
  bool decompiler_available_ = false;
};
}

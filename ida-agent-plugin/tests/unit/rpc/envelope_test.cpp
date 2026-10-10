#include "envelope.hpp"

#include "test_support.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

int main()
{
  using ida_agent::rpc::ErrorCode;
  using ida_agent::rpc::ParseErrorCode;
  using ida_agent::rpc::ParseRequest;
  using ida_agent::rpc::ParseResponse;
  using ida_agent::rpc::RpcError;
  using ida_agent::rpc::ValidateError;

  const auto request = ParseRequest(ReadFixture("valid", "request-system-ping.json"));
  Require(request.method == "system.ping", "request method mismatch");
  Require(request.timeout_ms == 5000, "request timeout mismatch");
  const auto equivalent_integer_request =
      ParseRequest(ReadFixture("valid", "request-integer-number-forms.json"));
  Require(equivalent_integer_request.timeout_ms == 5000, "equivalent integer timeout failed");
  static_cast<void>(ParseRequest(ReadFixture("valid", "request-extension-numbers.json")));
  const auto instance_request =
      ParseRequest(ReadFixture("valid", "request-instance-info.json"));
  Require(instance_request.method == "instance.info", "instance request method mismatch");
  const auto database_request =
      ParseRequest(ReadFixture("valid", "request-database-info.json"));
  Require(database_request.method == "database.info", "database request method mismatch");
  const auto function_request =
      ParseRequest(ReadFixture("valid", "request-function-get.json"));
  Require(function_request.method == "function.get", "function request method mismatch");
  const auto function_search_request =
      ParseRequest(ReadFixture("valid", "request-function-search.json"));
  Require(
      function_search_request.method == "function.search",
      "function search request method mismatch");
  const auto disassemble_request =
      ParseRequest(ReadFixture("valid", "request-function-disassemble.json"));
  Require(
      disassemble_request.method == "function.disassemble",
      "function disassemble request method mismatch");
  const auto basic_blocks_request =
      ParseRequest(ReadFixture("valid", "request-function-basic-blocks.json"));
  Require(
      basic_blocks_request.method == "function.basic_blocks",
      "function basic blocks request method mismatch");
  const auto callees_request =
      ParseRequest(ReadFixture("valid", "request-function-callees.json"));
  Require(
      callees_request.method == "function.callees",
      "function callees request method mismatch");
  const auto xref_request = ParseRequest(ReadFixture("valid", "request-xref-query.json"));
  Require(xref_request.method == "xref.query", "xref request method mismatch");
  const auto memory_request = ParseRequest(ReadFixture("valid", "request-memory-read.json"));
  Require(memory_request.method == "memory.read", "memory request method mismatch");
  const auto decompile_request =
      ParseRequest(ReadFixture("valid", "request-function-decompile.json"));
  Require(
      decompile_request.method == "function.decompile",
      "decompile request method mismatch");
  const auto script_request = ParseRequest(ReadFixture("valid", "request-script-execute.json"));
  Require(script_request.method == "script.execute", "script request method mismatch");
  for ( const std::string_view method_namespace :
        {"analysis", "changeset", "global", "instruction", "listing", "signature", "script"} )
  {
    const nlohmann::json encoded{
        {"protocolVersion", "ida-rpc/1"},
        {"requestId", "req-namespace"},
        {"sessionId", "session-namespace"},
        {"method", std::string(method_namespace) + ".test"},
        {"params", nlohmann::json::object()},
        {"timeoutMs", 5000},
    };
    const auto namespaced = ParseRequest(encoded.dump());
    Require(namespaced.method == encoded["method"], "registered method namespace rejected");
  }
  RequireFailure(
      []()
      {
        const nlohmann::json encoded{
            {"protocolVersion", "ida-rpc/1"},
            {"requestId", "req-namespace"},
            {"sessionId", "session-namespace"},
            {"method", "unknown.test"},
            {"params", nlohmann::json::object()},
            {"timeoutMs", 5000},
        };
        static_cast<void>(ParseRequest(encoded.dump()));
      },
      "unknown method namespace accepted");

  const auto success = ParseResponse(ReadFixture("valid", "response-system-ping.json"));
  Require(success.result.has_value(), "success result missing");
  Require(!success.error.has_value(), "success error present");
  static_cast<void>(ParseResponse(SerializeResponse(success)));
  static_cast<void>(ParseResponse(ReadFixture("valid", "response-extension-numbers.json")));
  const auto instance_response =
      ParseResponse(ReadFixture("valid", "response-instance-info.json"));
  Require(instance_response.result.has_value(), "instance response result missing");
  const auto database_response =
      ParseResponse(ReadFixture("valid", "response-database-info.json"));
  Require(database_response.result.has_value(), "database response result missing");
  const auto function_response =
      ParseResponse(ReadFixture("valid", "response-function-get.json"));
  Require(function_response.result.has_value(), "function response result missing");
  const auto function_search_response =
      ParseResponse(ReadFixture("valid", "response-function-search.json"));
  Require(function_search_response.result.has_value(), "function search response result missing");
  for ( const std::string_view fixture :
        {"response-function-disassemble.json", "response-function-basic-blocks.json",
         "response-function-callees.json"} )
  {
    const auto analysis_response = ParseResponse(ReadFixture("valid", fixture));
    Require(analysis_response.result.has_value(), "function analysis response result missing");
  }
  const auto xref_response = ParseResponse(ReadFixture("valid", "response-xref-query.json"));
  Require(xref_response.result.has_value(), "xref response result missing");
  const auto memory_response = ParseResponse(ReadFixture("valid", "response-memory-read.json"));
  Require(memory_response.result.has_value(), "memory response result missing");
  const auto decompile_response =
      ParseResponse(ReadFixture("valid", "response-function-decompile.json"));
  Require(decompile_response.result.has_value(), "decompile response result missing");
  const auto script_response = ParseResponse(ReadFixture("valid", "response-script-execute.json"));
  Require(script_response.result.has_value(), "script response result missing");

  const auto failure = ParseResponse(ReadFixture("valid", "response-error.json"));
  Require(failure.error.has_value(), "error response missing error");
  Require(failure.error->code == ErrorCode::InvalidArgument, "error code mismatch");
  static_cast<void>(ParseResponse(SerializeResponse(failure)));
  const auto recovery = ParseResponse(ReadFixture("valid", "response-error-recovery.json"));
  Require(recovery.error.has_value() && recovery.error->recovery_change_id.has_value(),
      "recovery error response missing change ID");
  Require(
      ParseResponse(SerializeResponse(recovery)).error->recovery_change_id == recovery.error->recovery_change_id,
      "recovery change ID did not round trip");

  for ( const std::string_view fixture :
        {"request-version-mismatch.json", "request-unknown-field.json",
         "request-invalid-params.json", "request-invalid-timeout.json",
         "request-missing-field.json", "request-malformed.json",
         "request-fractional-timeout.json", "request-high-precision-fraction.json"} )
  {
    RequireFailure(
        [fixture]() { static_cast<void>(ParseRequest(ReadFixture("invalid", fixture))); },
        "invalid request fixture accepted");
  }
  RequireFailure(
      []()
      {
        static_cast<void>(ParseResponse(ReadFixture("invalid", "response-result-and-error.json")));
      },
      "response with result and error accepted");

  const auto invalid_timeout_correlation = ida_agent::rpc::ParseRequestCorrelation(
      ReadFixture("invalid", "request-invalid-timeout.json"));
  Require(invalid_timeout_correlation.request_id == "req-0001", "correlation request ID mismatch");
  for ( const std::string_view fixture :
        {"response-missing-retryable.json", "response-missing-outcome.json",
         "response-error-recovery-code.json", "response-error-recovery-null.json"} )
  {
    RequireFailure(
        [fixture]() { static_cast<void>(ParseResponse(ReadFixture("invalid", fixture))); },
        "invalid response fixture accepted");
  }

  RequireFailure(
      []()
      {
        static_cast<void>(ParseRequest(std::string(ida_agent::rpc::MaxMessageBytes + 1, ' ')));
      },
      "oversized request accepted");

  const auto error_codes = nlohmann::json::parse(ReadFixture("valid", "error-codes.json"));
  Require(error_codes.size() == 11, "stable error code count mismatch");
  for ( const auto &code : error_codes )
    static_cast<void>(ParseErrorCode(code.get<std::string>()));

  std::string unicode_message;
  for ( std::size_t index = 0; index < 1024; ++index )
    unicode_message += "\xE7\x95\x8C";
  ValidateError(RpcError{ErrorCode::InternalError, unicode_message, false});
  unicode_message += "\xE7\x95\x8C";
  RequireFailure(
      [&unicode_message]()
      {
        ValidateError(RpcError{ErrorCode::InternalError, unicode_message, false});
      },
      "1025-character error message accepted");
  return 0;
}

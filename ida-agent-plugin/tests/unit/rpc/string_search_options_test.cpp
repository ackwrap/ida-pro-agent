#include "string_search_options.hpp"
#include "test_support.hpp"

int main()
{
  using ida_agent::rpc::ReadStringSearchRefresh;
  using Json = nlohmann::json;
  for ( const std::string name : {"string-search", "string-search-regex"} )
  {
    const auto read = [&name](const char *category, const char *suffix)
    {
      return ReadStringSearchRefresh(Json::parse(ReadFixture(
          category, "request-" + name + suffix + ".json")).at("params"));
    };
    Require(read("valid", "") == false, "omitted refresh must reuse the list");
    Require(read("valid", "-refresh") == true, "explicit refresh was rejected");
    Require(read("valid", "-continue") == false, "continuation must reuse the list");
    Require(!read("invalid", "-refresh-type"), "non-boolean refresh was accepted");
    Require(!read("invalid", "-refresh-cursor"), "refresh with cursor was accepted");
  }
  for ( const Json value : {Json(nullptr), Json(0), Json(1), Json::array(), Json::object()} )
    Require(!ReadStringSearchRefresh(Json{{"refresh", value}}), "invalid refresh type was accepted");
  Require(!ReadStringSearchRefresh(Json{{"refresh", true}, {"cursor", ""}}),
      "empty cursor bypassed the refresh conflict check");
  return 0;
}

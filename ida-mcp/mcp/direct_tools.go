package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type directToolSpec struct{ name, method, guidance string }

// These aliases bind to existing typed handlers, never to caller-selected RPCs.
var directToolSpecs = []directToolSpec{
	{"ida_list_instances", ToolInstancesList, "List running IDA databases. No parameters."},
	{"ida_select_instance", ToolInstancesSelect, "Select the database for subsequent calls. Use a discovered instanceId."},
	{"ida_database_info", ToolDatabaseInfo, "Inspect database metadata."},
	{"ida_get_function", ToolFunctionGet, "Inspect the function containing a hexadecimal address, for example 0x401000."},
	{"ida_search_functions", ToolFunctionSearch, "Search names using name (empty string lists functions). Continue with the returned cursor."},
	{"ida_decompile_function", ToolFunctionDecompile, "Read bounded pseudocode at address. Continue with nextOffset using offset."},
	{"ida_disassemble_function", ToolFunctionDisassemble, "Read bounded function instructions at address. Continue with nextOffset."},
	{"ida_function_callers", ToolFunctionCallers, "Read direct callers and call sites at address. Continue with nextOffset."},
	{"ida_function_callees", ToolFunctionCallees, "Read direct callees at address. Continue with nextOffset."},
	{"ida_query_xrefs", ToolXrefQuery, "Read incoming or outgoing references at address. Continue with the returned cursor."},
	{"ida_search_strings", ToolStringSearch, "Search strings using query. Continue with the returned cursor; refresh=true cannot be combined with cursor."},
	{"ida_read_memory", ToolMemoryRead, "Read memory at address. bytes/string require length; integer requires widthBits; pointer accepts neither."},
}

func registerDirectTools(server *mcp.Server, registry *toolRegistry, catalog *domainCatalog) error {
	for _, spec := range directToolSpecs {
		spec := spec
		method := catalog.byName[spec.method]
		if method == nil || method.Status != MethodCallable || method.SideEffect != "none" {
			return fmt.Errorf("direct tool %s has no callable read-only method", spec.name)
		}
		schema, err := directInputSchema(method)
		if err != nil {
			return err
		}
		compiled, err := compileCatalogSchema(spec.name, schema)
		if err != nil {
			return err
		}
		validator := &catalogMethod{Name: method.Name, compiledInput: compiled}
		description := spec.guidance
		autoRoute := method.Domain != DomainInstances
		if autoRoute {
			description += " Optional instanceId: use the selected instance, or the only available instance. With multiple databases, select one or provide instanceId."
		}
		registry.addBoundaryTool(server, &mcp.Tool{Name: spec.name, Description: description, InputSchema: schema, Annotations: domainAnnotations(true, false)}, func(ctx context.Context, request *mcp.CallToolRequest) (any, error) {
			traceStage(ctx, method.Name, "validate")
			raw := request.Params.Arguments
			if len(raw) == 0 {
				raw = json.RawMessage("{}")
			}
			// Check the simple alias contract before discovering or touching IDA.
			if err := validator.validate(raw); err != nil {
				return nil, invalidArguments(method.Name, err)
			}
			if err := method.validate(raw); err != nil {
				return nil, invalidArguments(method.Name, err)
			}
			ctx, cancel := methodContext(ctx, method)
			defer cancel()
			if autoRoute {
				traceStage(ctx, method.Name, "route")
				var err error
				raw, err = registry.routeDirectArguments(ctx, raw)
				if err != nil {
					return nil, methodFailure(method, err)
				}
			}
			output, err := registry.executeMethod(ctx, request, method, raw)
			if err != nil {
				return nil, methodFailure(method, err)
			}
			return output, nil
		})
	}
	return nil
}

func directInputSchema(method *catalogMethod) (json.RawMessage, error) {
	var schema map[string]any
	if err := json.Unmarshal(method.InputSchema, &schema); err != nil {
		return nil, err
	}
	// Combinations remain enforced by the method validator at execution time.
	for _, key := range []string{"oneOf", "anyOf", "allOf", "not"} {
		delete(schema, key)
	}
	if method.Name == ToolFunctionSearch {
		delete(schema["properties"].(map[string]any), "address")
		schema["required"] = []string{"name"}
	}
	return json.Marshal(schema)
}

func (registry *toolRegistry) routeDirectArguments(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var arguments map[string]json.RawMessage
	if err := json.Unmarshal(raw, &arguments); err != nil {
		return nil, err
	}
	if _, explicit := arguments["instanceId"]; explicit {
		return raw, nil
	}
	ctx, cancel := context.WithTimeout(ctx, instanceToolTimeout)
	defer cancel()
	instances, err := registry.instances.list(ctx)
	if err != nil {
		return nil, err
	}
	instanceID, err := registry.instances.resolve(nil)
	if err != nil {
		switch len(instances) {
		case 0:
			return nil, ida.NewError(ida.ErrorNotFound, "No running IDA database was found", false)
		case 1:
			instanceID = instances[0].InstanceID
		default:
			return nil, ida.NewError(ida.ErrorNotFound, "Multiple IDA databases are available; select an instance or provide instanceId", false)
		}
	}
	arguments["instanceId"], _ = json.Marshal(instanceID)
	return json.Marshal(arguments)
}

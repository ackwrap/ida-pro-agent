package mcpserver

import (
	"context"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const functionAnalysisInputSchema = `{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object","additionalProperties":false,"required":["address"],
  "properties":{
    "instanceId":` + instanceIDSchema + `,"address":` + addressSchema + `,
    "offset":{"type":"integer","minimum":0,"maximum":1000000,"default":0},
    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20}
  }
}`

type functionAnalysisInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Offset     uint32  `json:"offset,omitempty"`
	Limit      int     `json:"limit,omitempty"`
}

type disassemblyItemOutput struct {
	Address string `json:"address"`
	Text    string `json:"text"`
}

type functionDisassemblyOutput struct {
	EntryAddress string                  `json:"entryAddress"`
	Items        []disassemblyItemOutput `json:"items"`
	NextOffset   *uint32                 `json:"nextOffset"`
	HasMore      bool                    `json:"hasMore"`
}

type functionBasicBlockOutput struct {
	Start        string   `json:"start"`
	End          string   `json:"end"`
	Type         string   `json:"type"`
	Successors   []string `json:"successors"`
	Predecessors []string `json:"predecessors"`
}

type functionBasicBlocksOutput struct {
	EntryAddress string                     `json:"entryAddress"`
	Items        []functionBasicBlockOutput `json:"items"`
	NextOffset   *uint32                    `json:"nextOffset"`
	HasMore      bool                       `json:"hasMore"`
}

type functionCalleeOutput struct {
	Address  string `json:"address"`
	Name     string `json:"name"`
	Internal bool   `json:"internal"`
}

type functionCalleesOutput struct {
	EntryAddress string                 `json:"entryAddress"`
	Items        []functionCalleeOutput `json:"items"`
	NextOffset   *uint32                `json:"nextOffset"`
	HasMore      bool                   `json:"hasMore"`
}

func (registry *toolRegistry) functionDisassemble(
	ctx context.Context, _ *mcp.CallToolRequest, input functionAnalysisInput,
) (*mcp.CallToolResult, functionDisassemblyOutput, error) {
	ctx, params, instanceID, cancel, err := registry.prepareFunctionAnalysis(ctx, input)
	if err != nil {
		return nil, functionDisassemblyOutput{}, err
	}
	defer cancel()
	result, err := registry.backend.DisassembleFunction(ctx, instanceID, params)
	if err != nil {
		return nil, functionDisassemblyOutput{}, sanitizeToolError(err)
	}
	if err := result.Validate(params); err != nil {
		return nil, functionDisassemblyOutput{}, ida.NewError(ida.ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	output := functionDisassemblyOutput{
		EntryAddress: result.EntryAddress.String(), Items: make([]disassemblyItemOutput, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, item := range result.Items {
		output.Items = append(output.Items, disassemblyItemOutput{Address: item.Address.String(), Text: item.Text})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) functionBasicBlocks(
	ctx context.Context, _ *mcp.CallToolRequest, input functionAnalysisInput,
) (*mcp.CallToolResult, functionBasicBlocksOutput, error) {
	ctx, params, instanceID, cancel, err := registry.prepareFunctionAnalysis(ctx, input)
	if err != nil {
		return nil, functionBasicBlocksOutput{}, err
	}
	defer cancel()
	result, err := registry.backend.FunctionBasicBlocks(ctx, instanceID, params)
	if err != nil {
		return nil, functionBasicBlocksOutput{}, sanitizeToolError(err)
	}
	if err := result.Validate(params); err != nil {
		return nil, functionBasicBlocksOutput{}, ida.NewError(ida.ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	output := functionBasicBlocksOutput{
		EntryAddress: result.EntryAddress.String(), Items: make([]functionBasicBlockOutput, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, block := range result.Items {
		item := functionBasicBlockOutput{
			Start: block.Start.String(), End: block.End.String(), Type: string(block.Type),
			Successors:   make([]string, 0, len(block.Successors)),
			Predecessors: make([]string, 0, len(block.Predecessors)),
		}
		for _, address := range block.Successors {
			item.Successors = append(item.Successors, address.String())
		}
		for _, address := range block.Predecessors {
			item.Predecessors = append(item.Predecessors, address.String())
		}
		output.Items = append(output.Items, item)
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) functionCallees(
	ctx context.Context, _ *mcp.CallToolRequest, input functionAnalysisInput,
) (*mcp.CallToolResult, functionCalleesOutput, error) {
	ctx, params, instanceID, cancel, err := registry.prepareFunctionAnalysis(ctx, input)
	if err != nil {
		return nil, functionCalleesOutput{}, err
	}
	defer cancel()
	result, err := registry.backend.FunctionCallees(ctx, instanceID, params)
	if err != nil {
		return nil, functionCalleesOutput{}, sanitizeToolError(err)
	}
	if err := result.Validate(params); err != nil {
		return nil, functionCalleesOutput{}, ida.NewError(ida.ErrorInternal, "IDA backend returned invalid function analysis", false)
	}
	output := functionCalleesOutput{
		EntryAddress: result.EntryAddress.String(), Items: make([]functionCalleeOutput, 0, len(result.Items)),
		NextOffset: result.NextOffset, HasMore: result.HasMore,
	}
	for _, callee := range result.Items {
		output.Items = append(output.Items, functionCalleeOutput{
			Address: callee.Address.String(), Name: callee.Name, Internal: callee.Internal,
		})
	}
	return checkedCollectionOutput(output.Items, output)
}

func (registry *toolRegistry) prepareFunctionAnalysis(
	ctx context.Context, input functionAnalysisInput,
) (context.Context, ida.FunctionPageParams, string, context.CancelFunc, error) {
	if err := registry.ensureBackend(); err != nil {
		return ctx, ida.FunctionPageParams{}, "", func() {}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, readToolTimeout)
	instanceID, err := registry.instances.resolve(input.InstanceID)
	if err != nil {
		cancel()
		return ctx, ida.FunctionPageParams{}, "", func() {}, err
	}
	address, err := parseToolAddress(input.Address)
	if err != nil {
		cancel()
		return ctx, ida.FunctionPageParams{}, "", func() {}, err
	}
	params := ida.FunctionPageParams{Address: address, Offset: input.Offset, Limit: input.Limit}
	if err := params.Validate(); err != nil {
		cancel()
		return ctx, ida.FunctionPageParams{}, "", func() {}, ida.NewError(ida.ErrorInvalidArgument, "function analysis parameters are invalid", false)
	}
	return requestContext, params, instanceID, cancel, nil
}

package ida

import (
	"errors"
	"unicode/utf8"
)

const (
	maxFunctionAnalysisOffset = 1_000_000
	maxFunctionAnalysisLimit  = 100
	maxFunctionNextOffset     = maxFunctionAnalysisOffset + maxFunctionAnalysisLimit
)

type FunctionPageParams struct {
	Address Address
	Offset  uint32
	Limit   int
}

func (params FunctionPageParams) effectiveLimit() int {
	if params.Limit == 0 {
		return 20
	}
	return params.Limit
}

func (params FunctionPageParams) Validate() error {
	if params.Offset > maxFunctionAnalysisOffset {
		return errors.New("function analysis offset exceeds 1000000")
	}
	if params.Limit < 0 || params.Limit > maxFunctionAnalysisLimit {
		return errors.New("function analysis limit must be from 1 to 100")
	}
	return nil
}

type DisassemblyItem struct {
	Address Address `json:"address"`
	Text    string  `json:"text"`
}

type FunctionDisassemblyResult struct {
	EntryAddress Address           `json:"entryAddress"`
	Items        []DisassemblyItem `json:"items"`
	NextOffset   *uint32           `json:"nextOffset"`
	HasMore      bool              `json:"hasMore"`
}

func (result FunctionDisassemblyResult) Validate(params FunctionPageParams) error {
	if err := validateFunctionPage(params, len(result.Items), result.NextOffset, result.HasMore); err != nil {
		return err
	}
	var previous Address
	for index, item := range result.Items {
		if !utf8.ValidString(item.Text) || len(item.Text) > 4096 {
			return errors.New("disassembly text is not valid bounded UTF-8")
		}
		if index > 0 && item.Address <= previous {
			return errors.New("disassembly items are not strictly sorted")
		}
		previous = item.Address
	}
	return nil
}

type BasicBlockType string

const (
	BasicBlockNormal              BasicBlockType = "normal"
	BasicBlockIndirectJump        BasicBlockType = "indirect_jump"
	BasicBlockReturn              BasicBlockType = "return"
	BasicBlockConditionalReturn   BasicBlockType = "conditional_return"
	BasicBlockNoReturn            BasicBlockType = "no_return"
	BasicBlockExternalNoReturn    BasicBlockType = "external_no_return"
	BasicBlockExternal            BasicBlockType = "external"
	BasicBlockError               BasicBlockType = "error"
	maxFunctionBasicBlockEdgeList                = 64
)

type FunctionBasicBlock struct {
	Start        Address        `json:"start"`
	End          Address        `json:"end"`
	Type         BasicBlockType `json:"type"`
	Successors   []Address      `json:"successors"`
	Predecessors []Address      `json:"predecessors"`
}

type FunctionBasicBlocksResult struct {
	EntryAddress Address              `json:"entryAddress"`
	Items        []FunctionBasicBlock `json:"items"`
	NextOffset   *uint32              `json:"nextOffset"`
	HasMore      bool                 `json:"hasMore"`
}

func (result FunctionBasicBlocksResult) Validate(params FunctionPageParams) error {
	if err := validateFunctionPage(params, len(result.Items), result.NextOffset, result.HasMore); err != nil {
		return err
	}
	validTypes := map[BasicBlockType]bool{
		BasicBlockNormal: true, BasicBlockIndirectJump: true, BasicBlockReturn: true,
		BasicBlockConditionalReturn: true, BasicBlockNoReturn: true,
		BasicBlockExternalNoReturn: true, BasicBlockExternal: true, BasicBlockError: true,
	}
	var previous Address
	for index, block := range result.Items {
		if block.Start >= block.End {
			return errors.New("basic block range is empty or reversed")
		}
		if !validTypes[block.Type] {
			return errors.New("basic block type is invalid")
		}
		if block.Successors == nil || block.Predecessors == nil ||
			len(block.Successors) > maxFunctionBasicBlockEdgeList ||
			len(block.Predecessors) > maxFunctionBasicBlockEdgeList {
			return errors.New("basic block edge list is invalid")
		}
		if index > 0 && block.Start <= previous {
			return errors.New("basic blocks are not strictly sorted")
		}
		previous = block.Start
	}
	return nil
}

type FunctionCallee struct {
	Address  Address `json:"address"`
	Name     string  `json:"name"`
	Internal bool    `json:"internal"`
}

type FunctionCalleesResult struct {
	EntryAddress Address          `json:"entryAddress"`
	Items        []FunctionCallee `json:"items"`
	NextOffset   *uint32          `json:"nextOffset"`
	HasMore      bool             `json:"hasMore"`
}

func (result FunctionCalleesResult) Validate(params FunctionPageParams) error {
	if err := validateFunctionPage(params, len(result.Items), result.NextOffset, result.HasMore); err != nil {
		return err
	}
	var previous Address
	for index, callee := range result.Items {
		if !utf8.ValidString(callee.Name) {
			return errors.New("callee name is not valid UTF-8")
		}
		if length := utf8.RuneCountInString(callee.Name); length < 1 || length > 1024 {
			return errors.New("callee name must contain 1 to 1024 characters")
		}
		if index > 0 && callee.Address <= previous {
			return errors.New("callees are not strictly sorted")
		}
		previous = callee.Address
	}
	return nil
}

func validateFunctionPage(params FunctionPageParams, itemCount int, nextOffset *uint32, hasMore bool) error {
	if err := params.Validate(); err != nil {
		return err
	}
	if itemCount > params.effectiveLimit() {
		return errors.New("function analysis result exceeds the requested limit")
	}
	if hasMore != (nextOffset != nil) {
		return errors.New("function analysis pagination metadata is inconsistent")
	}
	if nextOffset != nil {
		expected := uint64(params.Offset) + uint64(itemCount)
		if itemCount == 0 || expected > maxFunctionNextOffset || uint64(*nextOffset) != expected {
			return errors.New("function analysis continuation is invalid")
		}
	}
	return nil
}

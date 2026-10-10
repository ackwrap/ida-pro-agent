package mcpserver

import "ida-mcp/ida"

type readonlyAddressInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
}
type readonlyPageInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Address    string  `json:"address"`
	Offset     uint32  `json:"offset,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
}
type addressListInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Start      *string `json:"start,omitempty"`
	End        *string `json:"end,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}
type analysisStatusInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
}
type analysisWaitInput struct {
	InstanceID     *string `json:"instanceId,omitempty"`
	TimeoutMs      uint32  `json:"timeoutMs,omitempty"`
	PollIntervalMs uint32  `json:"pollIntervalMs,omitempty"`
}
type analysisPlanInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Start      string  `json:"start"`
	End        string  `json:"end"`
	Confirm    bool    `json:"confirm"`
}
type analysisProblemsInput struct {
	InstanceID *string `json:"instanceId,omitempty"`
	Type       string  `json:"type"`
	Start      *string `json:"start,omitempty"`
	Limit      uint32  `json:"limit,omitempty"`
	Cursor     string  `json:"cursor,omitempty"`
}

type fixupListOutput struct {
	Items      []ida.FixupItem `json:"items"`
	NextCursor *string         `json:"nextCursor"`
	HasMore    bool            `json:"hasMore"`
}

type analysisProblemsOutput struct {
	Items      []ida.AnalysisProblem `json:"items"`
	NextCursor *string               `json:"nextCursor"`
	HasMore    bool                  `json:"hasMore"`
}

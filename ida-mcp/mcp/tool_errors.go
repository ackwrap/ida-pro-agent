package mcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"ida-mcp/ida"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

type argumentIssue struct {
	Field    string `json:"field"`
	Rule     string `json:"rule"`
	Expected string `json:"expected"`
}

type toolFailure struct {
	Code             ida.ErrorCode   `json:"code"`
	Message          string          `json:"message"`
	Method           string          `json:"method,omitempty"`
	Retryable        bool            `json:"retryable"`
	Hint             string          `json:"hint"`
	Issues           []argumentIssue `json:"issues,omitempty"`
	RecoveryChangeID string          `json:"recoveryChangeId,omitempty"`
	ExecutionState   string          `json:"executionState,omitempty"`
}

func (failure *toolFailure) Error() string {
	return string(failure.Code) + ": " + failure.Message
}

func invalidArguments(method string, err error) *toolFailure {
	failure := &toolFailure{
		Code: ida.ErrorInvalidArgument, Message: "Tool arguments do not match the required contract",
		Method: method, Hint: "Correct the listed fields. Omit unused optional fields; do not send null or JSON strings in place of objects.",
	}
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		failure.Issues = []argumentIssue{{Field: "arguments", Rule: "object", Expected: "one JSON object without trailing data"}}
		return failure
	}
	collectArgumentIssues(validation, &failure.Issues)
	if len(failure.Issues) == 0 {
		failure.Issues = []argumentIssue{{Field: "arguments", Rule: "schema", Expected: "parameters from action=describe"}}
	}
	return failure
}

var safeFieldToken = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func issueField(tokens []string) string {
	parts := []string{"arguments"}
	for _, token := range tokens {
		if !safeFieldToken.MatchString(token) {
			token = "[field]"
		}
		parts = append(parts, token)
	}
	return strings.Join(parts, ".")
}

func addArgumentIssue(issues *[]argumentIssue, issue argumentIssue) {
	if len(*issues) >= 8 {
		return
	}
	for _, previous := range *issues {
		if previous == issue {
			return
		}
	}
	*issues = append(*issues, issue)
}

func collectArgumentIssues(validation *jsonschema.ValidationError, issues *[]argumentIssue) {
	field := issueField(validation.InstanceLocation)
	add := func(rule, expected string) {
		addArgumentIssue(issues, argumentIssue{Field: field, Rule: rule, Expected: expected})
	}
	switch problem := validation.ErrorKind.(type) {
	case *kind.Type:
		add("type", strings.Join(problem.Want, " or "))
	case *kind.Required:
		for _, missing := range problem.Missing {
			path := append(append([]string{}, validation.InstanceLocation...), missing)
			addArgumentIssue(issues, argumentIssue{Field: issueField(path), Rule: "required", Expected: "provide this field"})
		}
	case *kind.AdditionalProperties:
		for _, property := range problem.Properties {
			path := append(append([]string{}, validation.InstanceLocation...), property)
			addArgumentIssue(issues, argumentIssue{Field: issueField(path), Rule: "additionalProperties", Expected: "remove this unknown field"})
		}
	case *kind.Minimum:
		add("minimum", "at least "+problem.Want.FloatString(0))
	case *kind.Maximum:
		add("maximum", "at most "+problem.Want.FloatString(0))
	case *kind.Enum:
		allowed, _ := json.Marshal(problem.Want)
		add("enum", string(allowed))
	case *kind.Pattern:
		add("pattern", "match the documented format (addresses are hexadecimal strings, instanceId is a discovered UUID)")
	case *kind.MinLength:
		add("minLength", fmt.Sprintf("at least %d characters", problem.Want))
	case *kind.MaxLength:
		add("maxLength", fmt.Sprintf("at most %d characters", problem.Want))
	case *kind.OneOf:
		add("oneOf", "exactly one parameter combination from action=describe")
		return
	default:
		if len(validation.Causes) == 0 {
			path := validation.ErrorKind.KeywordPath()
			rule := "schema"
			if len(path) > 0 {
				rule = path[0]
			}
			add(rule, "satisfy the constraint returned by action=describe")
		}
	}
	for _, cause := range validation.Causes {
		collectArgumentIssues(cause, issues)
		if len(*issues) >= 8 {
			break
		}
	}
}

func methodFailure(method *catalogMethod, err error) *toolFailure {
	var existing *toolFailure
	if errors.As(err, &existing) {
		if existing.Method == "" && method.Name != "" {
			copy := *existing
			copy.Method = method.Name
			return &copy
		}
		return existing
	}
	sanitized := sanitizeToolError(err)
	var backend *ida.Error
	if !errors.As(sanitized, &backend) {
		backend = ida.NewError(ida.ErrorInternal, "IDA operation failed", false)
	}
	failure := &toolFailure{
		Code: backend.Code, Message: backend.Message, Method: method.Name,
		Retryable: backend.Retryable, RecoveryChangeID: backend.RecoveryChangeID,
		Hint: "Use action=describe for this method's parameters and requirements.",
	}
	switch backend.Code {
	case ida.ErrorNotFound:
		failure.Hint = "List instances with ida_list_instances; select the intended database or provide instanceId. Verify that the requested IDB item exists."
	case ida.ErrorIDABusy:
		failure.Hint = "Wait briefly and reduce parallel IDA requests. Retry only if retryable is true."
	case ida.ErrorTimeout:
		if method.SideEffect != "none" {
			failure.Retryable = false
			failure.ExecutionState = "unknown"
			failure.Hint = "The operation may have started. Check IDA state and ChangeSet audit before retrying; a timeout does not roll back an operation."
		} else {
			failure.Hint = "Reduce the analysis scope or page size, check IDA responsiveness, then retry the read if needed."
		}
	case ida.ErrorOutputLimit:
		failure.Hint = "Reduce limit/maxBytes and use this method's continuation fields."
	case ida.ErrorPermissionDenied:
		failure.Retryable = false
		failure.Hint = "Check the MCP client's permission policy and any pending permission dialog in IDA."
	case ida.ErrorCapabilityUnavailable:
		failure.Retryable = false
		failure.Hint = "Check the selected IDA database, decompiler/debugger capabilities and the method requirements."
	}
	return failure
}

func unavailableMethod(catalog *domainCatalog, name string) *toolFailure {
	failure := &toolFailure{Code: ida.ErrorNotFound, Message: "The method is not available in this domain", Hint: "Call this tool with action=list, then action=describe using an exact returned method name."}
	if known, ok := catalog.byName[name]; ok {
		failure.Hint = "Use " + domainToolNames[known.Domain] + " with action=describe for " + known.Name + "."
	}
	return failure
}

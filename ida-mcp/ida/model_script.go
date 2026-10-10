package ida

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxScriptSourceBytes = 32 * 1024

type ScriptExecuteParams struct {
	Language string `json:"language"`
	Code     string `json:"code"`
}

type ScriptExecutionResult struct {
	Language     string  `json:"language"`
	Success      bool    `json:"success"`
	Result       *string `json:"result"`
	Stdout       string  `json:"stdout"`
	Stderr       string  `json:"stderr"`
	Truncated    bool    `json:"truncated"`
	OriginalSize uint64  `json:"originalSize"`
}

func (params ScriptExecuteParams) Validate() error {
	if params.Language != "python" && params.Language != "idc" {
		return errors.New("script language is invalid")
	}
	if params.Code == "" || len(params.Code) > MaxScriptSourceBytes || strings.IndexByte(params.Code, 0) >= 0 || !utf8.ValidString(params.Code) {
		return errors.New("script source is invalid")
	}
	return nil
}

func (result ScriptExecutionResult) Validate(expectedLanguage string) error {
	if result.Language != expectedLanguage || len(result.Stdout) > 32*1024 || len(result.Stderr) > 32*1024 || !utf8.ValidString(result.Stdout) || !utf8.ValidString(result.Stderr) {
		return errors.New("script result is invalid")
	}
	captured := len(result.Stdout) + len(result.Stderr)
	if result.Result != nil {
		if len(*result.Result) > 32*1024 || !utf8.ValidString(*result.Result) {
			return errors.New("script result value is invalid")
		}
		captured += len(*result.Result)
	}
	if (!result.Truncated && result.OriginalSize != uint64(captured)) || (result.Truncated && result.OriginalSize <= uint64(captured)) {
		return errors.New("script result size is invalid")
	}
	return nil
}

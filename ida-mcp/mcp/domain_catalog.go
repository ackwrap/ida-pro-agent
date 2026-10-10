package mcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	ToolDomainInstances = "ida_instances"
	ToolDomainDatabase  = "ida_database"
	ToolDomainFunctions = "ida_functions"
	ToolDomainSearch    = "ida_search"
	ToolDomainSymbols   = "ida_symbols"
	ToolDomainTypes     = "ida_types"
	ToolDomainAnalysis  = "ida_analysis"
	ToolDomainChanges   = "ida_changes"
	ToolDomainPatch     = "ida_patch"
	ToolDomainDebugger  = "ida_debugger"
	ToolDomainScripts   = "ida_scripts"

	DomainInstances = "instances"
	DomainDatabase  = "database"
	DomainFunctions = "functions"
	DomainSearch    = "search"
	DomainSymbols   = "symbols"
	DomainTypes     = "types"
	DomainAnalysis  = "analysis"
	DomainChanges   = "changes"
	DomainPatch     = "patch"
	DomainDebugger  = "debugger"
	DomainScripts   = "scripts"

	MethodCallable = "callable"
	MethodInternal = "internal"
	MethodPlanned  = "planned"
	MethodDeferred = "deferred"
)

var domainToolNames = map[string]string{
	DomainInstances: ToolDomainInstances,
	DomainDatabase:  ToolDomainDatabase,
	DomainFunctions: ToolDomainFunctions,
	DomainSearch:    ToolDomainSearch,
	DomainSymbols:   ToolDomainSymbols,
	DomainTypes:     ToolDomainTypes,
	DomainAnalysis:  ToolDomainAnalysis,
	DomainChanges:   ToolDomainChanges,
	DomainPatch:     ToolDomainPatch,
	DomainDebugger:  ToolDomainDebugger,
	DomainScripts:   ToolDomainScripts,
}

type catalogMethod struct {
	Name          string
	Domain        string
	Summary       string
	Status        string
	Source        string
	Capability    string
	SideEffect    string
	Parameters    string
	Output        string
	InputSchema   json.RawMessage
	TimeoutMs     int
	compiledInput *jsonschema.Schema
}

type domainCatalog struct {
	byName   map[string]*catalogMethod
	byDomain map[string][]*catalogMethod
}

func newDomainCatalog() (*domainCatalog, error) {
	catalog := &domainCatalog{
		byName: make(map[string]*catalogMethod), byDomain: make(map[string][]*catalogMethod),
	}
	for _, method := range catalogMethods() {
		if _, exists := domainToolNames[method.Domain]; !exists {
			return nil, fmt.Errorf("catalog method %s has unknown domain %s", method.Name, method.Domain)
		}
		if _, exists := catalog.byName[method.Name]; exists {
			return nil, fmt.Errorf("catalog method %s is duplicated", method.Name)
		}
		entry := method
		if entry.Status == MethodCallable {
			if len(entry.InputSchema) == 0 {
				return nil, fmt.Errorf("callable catalog method %s has no input schema", entry.Name)
			}
			compiled, err := compileCatalogSchema(entry.Name, entry.InputSchema)
			if err != nil {
				return nil, err
			}
			entry.compiledInput = compiled
		}
		catalog.byName[entry.Name] = &entry
		catalog.byDomain[entry.Domain] = append(catalog.byDomain[entry.Domain], &entry)
	}
	for domain := range domainToolNames {
		methods := catalog.byDomain[domain]
		sort.Slice(methods, func(i, j int) bool { return methods[i].Name < methods[j].Name })
	}
	return catalog, nil
}

func compileCatalogSchema(name string, schema json.RawMessage) (*jsonschema.Schema, error) {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(schema))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode catalog schema for %s: %w", name, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	location := "https://ida-agent.local/catalog/" + strings.ReplaceAll(name, ".", "-") + ".json"
	if err := compiler.AddResource(location, document); err != nil {
		return nil, fmt.Errorf("load catalog schema for %s: %w", name, err)
	}
	compiled, err := compiler.Compile(location)
	if err != nil {
		return nil, fmt.Errorf("compile catalog schema for %s: %w", name, err)
	}
	return compiled, nil
}

func (catalog *domainCatalog) method(domain, name string) (*catalogMethod, bool) {
	method, ok := catalog.byName[name]
	return method, ok && method.Domain == domain
}

func (catalog *domainCatalog) methods(domain string) []*catalogMethod {
	return catalog.byDomain[domain]
}

func DomainToolForMethod(name string) (string, bool) {
	for _, method := range catalogMethods() {
		if method.Name == name && method.Status == MethodCallable {
			return domainToolNames[method.Domain], true
		}
	}
	return "", false
}

func (method *catalogMethod) validate(arguments json.RawMessage) error {
	if method == nil || method.compiledInput == nil {
		return fmt.Errorf("method is not callable")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(arguments))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("arguments are not valid JSON: %w", err)
	}
	if err := ensureJSONDecoderEnd(decoder); err != nil {
		return fmt.Errorf("arguments are not valid JSON: %w", err)
	}
	if err := method.compiledInput.Validate(value); err != nil {
		return fmt.Errorf("arguments do not match %s: %w", method.Name, err)
	}
	return nil
}

func ensureJSONDecoderEnd(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == nil {
		return fmt.Errorf("value contains trailing JSON")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

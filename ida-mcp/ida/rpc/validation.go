package rpc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
)

var (
	identifierPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	uuidV4Pattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	methodPattern           = regexp.MustCompile(`^(system|instance|database|function|string|decompiler|xref|symbol|type|memory|instruction|listing|signature|global|patch|analysis|changeset|debugger|script|ui|fixup|switch|exception|source|name|comment|bookmark)\.[a-z][a-z0-9_]*$`)
	archPattern             = regexp.MustCompile(`^[A-Za-z0-9._+\-]{1,64}$`)
	recoveryChangeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`)
)

func validateProtocolVersion(version string) error {
	if version != ProtocolVersion {
		return fmt.Errorf("unsupported protocolVersion %q", version)
	}
	return nil
}

func isJSONObject(data []byte) bool {
	var object map[string]json.RawMessage
	return json.Unmarshal(data, &object) == nil && object != nil
}

type wireUint32 uint32

func (value *wireUint32) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] == '"' {
		return fmt.Errorf("value must be an integer")
	}
	parsed, err := parseWireUint32(string(data))
	if err != nil {
		return err
	}
	*value = wireUint32(parsed)
	return nil
}

func parseWireUint32(encoded string) (uint32, error) {
	value, ok := new(big.Rat).SetString(encoded)
	if !ok || value.Sign() < 0 || !value.IsInt() || !value.Num().IsUint64() {
		return 0, fmt.Errorf("value must be an unsigned 32-bit integer")
	}
	integer := value.Num().Uint64()
	if integer > uint64(^uint32(0)) {
		return 0, fmt.Errorf("value must be an unsigned 32-bit integer")
	}
	return uint32(integer), nil
}

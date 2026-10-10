package rpc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Address is an unsigned IDA address encoded as a hexadecimal JSON string.
type Address uint64

func ParseAddress(value string) (Address, error) {
	if !strings.HasPrefix(value, "0x") {
		return 0, fmt.Errorf("address %q must start with 0x", value)
	}
	digits := value[2:]
	if len(digits) == 0 || len(digits) > 16 {
		return 0, fmt.Errorf("address %q must contain 1 to 16 hexadecimal digits", value)
	}
	parsed, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q: %w", value, err)
	}
	return Address(parsed), nil
}

func (address Address) String() string {
	return fmt.Sprintf("0x%x", uint64(address))
}

func (address Address) MarshalJSON() ([]byte, error) {
	return json.Marshal(address.String())
}

func (address *Address) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("address must be a hexadecimal string: %w", err)
	}
	parsed, err := ParseAddress(encoded)
	if err != nil {
		return err
	}
	*address = parsed
	return nil
}

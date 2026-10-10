package bridge

import (
	"context"
	"errors"

	"ida-mcp/ida/rpc"
)

const methodInstanceInfo = "instance.info"

type InstanceInfo struct {
	InstanceID   string                   `json:"instance_id"`
	PID          uint32                   `json:"pid"`
	IDAVersion   string                   `json:"ida_version"`
	Database     string                   `json:"database"`
	InputFile    string                   `json:"input_file"`
	Processor    string                   `json:"processor"`
	Bitness      int                      `json:"bitness"`
	Architecture string                   `json:"architecture"`
	Capabilities rpc.InstanceCapabilities `json:"capabilities"`
}

func (client *Client) InstanceInfo(
	ctx context.Context,
	instance rpc.InstanceDescriptor,
) (InstanceInfo, error) {
	result, err := callTyped[struct{}, InstanceInfo](client, ctx, instance, methodInstanceInfo, struct{}{})
	if err != nil {
		return InstanceInfo{}, err
	}
	if result.InstanceID != instance.InstanceID || result.PID != instance.PID {
		return InstanceInfo{}, errors.New("instance.info identity mismatch")
	}
	if result.Bitness != 32 && result.Bitness != 64 {
		return InstanceInfo{}, errors.New("instance.info bitness is invalid")
	}
	if result.IDAVersion == "" || result.Processor == "" || result.Architecture == "" ||
		result.Capabilities.AddressBits != result.Bitness {
		return InstanceInfo{}, errors.New("instance.info metadata is invalid")
	}
	return result, nil
}

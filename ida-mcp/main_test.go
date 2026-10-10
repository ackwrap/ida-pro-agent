package main

import "testing"

func TestValidateListenAddress(t *testing.T) {
	for _, valid := range []string{"127.0.0.1:8743", "[::1]:8743"} {
		if err := validateListenAddress(valid); err != nil {
			t.Errorf("%s: %v", valid, err)
		}
	}
	for _, invalid := range []string{"0.0.0.0:8743", "192.0.2.1:8743", "localhost:8743"} {
		if err := validateListenAddress(invalid); err == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}

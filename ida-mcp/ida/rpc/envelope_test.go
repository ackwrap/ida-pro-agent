package rpc

import "testing"

func TestDecodeValidRequestFixture(t *testing.T) {
	t.Parallel()

	request, err := DecodeRequest(readFixture(t, "valid", "request-system-ping.json"))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if request.Method != "system.ping" || request.TimeoutMs != 5000 {
		t.Fatalf("request = %+v", request)
	}
}

func TestDecodeEquivalentIntegerRequestFixture(t *testing.T) {
	t.Parallel()

	request, err := DecodeRequest(readFixture(t, "valid", "request-integer-number-forms.json"))
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if request.TimeoutMs != 5000 {
		t.Fatalf("timeoutMs = %d", request.TimeoutMs)
	}
}

func TestDecodeRequestAllowsMethodSpecificNumbers(t *testing.T) {
	t.Parallel()

	if _, err := DecodeRequest(readFixture(t, "valid", "request-extension-numbers.json")); err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
}

func TestDecodeInvalidRequestFixtures(t *testing.T) {
	t.Parallel()

	fixtures := []string{
		"request-version-mismatch.json",
		"request-unknown-field.json",
		"request-invalid-params.json",
		"request-invalid-timeout.json",
		"request-missing-field.json",
		"request-malformed.json",
		"request-fractional-timeout.json",
		"request-high-precision-fraction.json",
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRequest(readFixture(t, "invalid", fixture)); err == nil {
				t.Fatal("DecodeRequest succeeded")
			}
		})
	}
}

func TestDecodeValidResponseFixtures(t *testing.T) {
	t.Parallel()

	for _, fixture := range []string{"response-system-ping.json", "response-error.json", "response-error-recovery.json", "response-extension-numbers.json"} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeResponse(readFixture(t, "valid", fixture)); err != nil {
				t.Fatalf("DecodeResponse: %v", err)
			}
		})
	}
}

func TestDecodeInvalidResponseFixtures(t *testing.T) {
	t.Parallel()

	for _, fixture := range []string{
		"response-result-and-error.json",
		"response-missing-retryable.json",
		"response-missing-outcome.json",
		"response-error-recovery-code.json",
		"response-error-recovery-null.json",
	} {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeResponse(readFixture(t, "invalid", fixture)); err == nil {
				t.Fatal("DecodeResponse succeeded")
			}
		})
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	t.Parallel()

	data := append(readFixture(t, "valid", "request-system-ping.json"), []byte("{}")...)
	if _, err := DecodeRequest(data); err == nil {
		t.Fatal("DecodeRequest succeeded")
	}
}

func TestDecodeRejectsOversizedMessage(t *testing.T) {
	t.Parallel()

	if _, err := DecodeRequest(make([]byte, MaxMessageBytes+1)); err == nil {
		t.Fatal("DecodeRequest succeeded")
	}
}

//go:build windows

package webmanager

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestOpenCodeConfigurationPreservesWindowsDACL(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	configPath := filepath.Join(home, ".config", "opencode", "opencode.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// Use an explicit ACL with an additional principal. Inherited temp-directory
	// ACLs can be canonicalized or duplicated by ReplaceFile on Windows Server.
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FR;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(configPath, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(
		configPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	manager := newClientManager(gateway, home, nil, nil)
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(
		configPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fileACLRules(t, before), fileACLRules(t, after)) {
		t.Fatalf("DACL changed:\nbefore: %s\nafter:  %s", before.String(), after.String())
	}
	assertProtectedDACL(t, after)
}

func TestNewOpenCodeConfigurationUsesCurrentUserDACL(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	manager := newClientManager(filepath.Join(home, "ida-mcp.exe"), home, nil, nil)
	if err := manager.configureOpenCode(true); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".config", "opencode", "opencode.json")
	descriptor, err := windows.GetNamedSecurityInfo(
		configPath, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	rules := fileACLRules(t, descriptor)
	// SDDL renders built-in Administrator as LA on hosted runners. Compare the
	// actual SID, not its display alias, and reject every extra access entry.
	if len(rules) != 1 || rules[0].sid != user.User.Sid.String() ||
		rules[0].kind != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("new config DACL is not current-user-only: %s", descriptor.String())
	}
	assertProtectedDACL(t, descriptor)
}

type fileACLRule struct {
	kind  uint8
	flags uint8
	mask  windows.ACCESS_MASK
	sid   string
}

func fileACLRules(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) []fileACLRule {
	t.Helper()
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("missing DACL: %v", err)
	}
	rules := make([]fileACLRule, 0, dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var entry *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && entry.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			t.Fatalf("unexpected ACE type: %d", entry.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&entry.SidStart))
		rules = append(rules, fileACLRule{entry.Header.AceType, entry.Header.AceFlags, entry.Mask, sid.String()})
	}
	return rules
}

func assertProtectedDACL(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected from inherited permissions: %v, %s", err, descriptor.String())
	}
}

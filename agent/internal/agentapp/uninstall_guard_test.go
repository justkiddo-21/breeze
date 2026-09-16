package agentapp

import "testing"

func TestHashUninstallPassword(t *testing.T) {
	t.Run("empty password rejected", func(t *testing.T) {
		if _, err := hashUninstallPassword(""); err == nil {
			t.Fatal("expected error for empty password")
		}
	})

	t.Run("hash verifies against the right password", func(t *testing.T) {
		stored, err := hashUninstallPassword("s3cret-pw")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if !verifyUninstallPassword(stored, "s3cret-pw") {
			t.Fatal("correct password did not verify")
		}
		if verifyUninstallPassword(stored, "wrong") {
			t.Fatal("wrong password verified")
		}
		if verifyUninstallPassword(stored, "") {
			t.Fatal("empty password verified")
		}
	})

	t.Run("distinct salts produce distinct hashes for the same password", func(t *testing.T) {
		a, err := hashUninstallPassword("same")
		if err != nil {
			t.Fatalf("hash a: %v", err)
		}
		b, err := hashUninstallPassword("same")
		if err != nil {
			t.Fatalf("hash b: %v", err)
		}
		if a == b {
			t.Fatal("expected salted hashes to differ")
		}
		// Both must still verify.
		if !verifyUninstallPassword(a, "same") || !verifyUninstallPassword(b, "same") {
			t.Fatal("salted hashes must both verify the original password")
		}
	})

	t.Run("malformed stored values never verify", func(t *testing.T) {
		for _, bad := range []string{"", "nocolon", "nothex:deadbeef", "dead:nothex", ":", "aa:"} {
			if verifyUninstallPassword(bad, "anything") {
				t.Fatalf("malformed stored value %q verified", bad)
			}
		}
	})
}

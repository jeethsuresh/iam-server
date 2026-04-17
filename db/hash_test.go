package db

import "testing"

func TestHashPasswordVerifyPassword(t *testing.T) {
	salt, err := generateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hashPassword("short-pw", salt, PEPPER)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, "short-pw", salt, PEPPER) {
		t.Fatal("verify should succeed")
	}
	if verifyPassword(hash, "wrong", salt, PEPPER) {
		t.Fatal("verify should fail for wrong password")
	}
	if verifyPassword(hash, "short-pw", "othersalt", PEPPER) {
		t.Fatal("wrong salt should fail")
	}
}

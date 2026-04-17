package db

import (
	"testing"
)

func TestOpenFromEnv_NoEnv(t *testing.T) {
	t.Setenv("USE_POSTGRES", "")
	t.Setenv("USE_SQLITE", "")
	_, err := OpenFromEnv()
	if err == nil {
		t.Fatal("expected error")
	}
}

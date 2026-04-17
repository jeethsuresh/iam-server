package auth

import (
	"net"
	"os"
	"testing"
)

func TestValidateCallbackURL_IPRanges(t *testing.T) {
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
	cases := []struct {
		raw     string
		wantErr bool
	}{
		{"https://1.1.1.1/token", false},
		{"http://127.0.0.1:8080/cb", true},
		{"http://10.0.0.1/x", true},
		{"http://192.168.1.1/x", true},
		{"http://169.254.169.254/latest/meta-data", true},
		{"javascript:alert(1)", true},
	}
	for _, tc := range cases {
		err := ValidateCallbackURL(tc.raw, "u")
		if tc.wantErr && err == nil {
			t.Errorf("%q: want error", tc.raw)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q: %v", tc.raw, err)
		}
	}
}

func TestValidateCallbackURL_Relaxed(t *testing.T) {
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")
	defer os.Unsetenv("IAM_RELAXED_CALLBACK_URLS")

	if err := ValidateCallbackURL("http://127.0.0.1:9/x", "u"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateIPMetadataRange(t *testing.T) {
	ip := net.ParseIP("169.254.1.1")
	if err := validateIP(ip, false, "t"); err == nil {
		t.Fatal("expected error for 169.254.x.x")
	}
	if err := validateIP(ip, true, "t"); err == nil {
		t.Fatal("169.254.x.x must be blocked even when relaxed")
	}
}

func TestValidateCallbackURL_SchemeAndShape(t *testing.T) {
	t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
	cases := []struct {
		raw     string
		wantErr bool
	}{
		{"/relative-only", true},
		{"ftp://1.1.1.1/x", true},
		{"https://", true},
		{"http://1.1.1.1:8080/path", false},
	}
	for _, tc := range cases {
		err := ValidateCallbackURL(tc.raw, "u")
		if tc.wantErr && err == nil {
			t.Errorf("%q: want error", tc.raw)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q: %v", tc.raw, err)
		}
	}
}

func TestValidateCallbackURL_IPv6Loopback(t *testing.T) {
	t.Run("strict", func(t *testing.T) {
		t.Setenv("IAM_RELAXED_CALLBACK_URLS", "")
		if err := ValidateCallbackURL("http://[::1]:9/x", "u"); err == nil {
			t.Fatal("::1 should be blocked without relaxed")
		}
	})
	t.Run("relaxed", func(t *testing.T) {
		t.Setenv("IAM_RELAXED_CALLBACK_URLS", "1")
		if err := ValidateCallbackURL("http://[::1]:9/x", "u"); err != nil {
			t.Fatal(err)
		}
	})
}

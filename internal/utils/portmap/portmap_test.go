package portmap

import (
	"reflect"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		entry string
		want  []Mapping
	}{
		{"443", []Mapping{{":443", "443"}}},
		{" 443 ", []Mapping{{":443", "443"}}},
		{"1", []Mapping{{":1", "1"}}},
		{"65535", []Mapping{{":65535", "65535"}}},
		{"443-445", []Mapping{{":443", "443"}, {":444", "444"}, {":445", "445"}}},
		{"443-444:5201", []Mapping{{":443", "5201"}, {":444", "5201"}}},
		{"443-444=1.1.1.1:5201", []Mapping{{":443", "1.1.1.1:5201"}, {":444", "1.1.1.1:5201"}}},
		{"4000=5000", []Mapping{{":4000", "5000"}}},
		{"1=5000", []Mapping{{":1", "5000"}}},
		{"65535=5000", []Mapping{{":65535", "5000"}}},
		{"443 = 5201", []Mapping{{":443", "5201"}}},
		{"127.0.0.2:443=5201", []Mapping{{"127.0.0.2:443", "5201"}}},
		{"443=1.1.1.1:5201", []Mapping{{":443", "1.1.1.1:5201"}}},
		{"127.0.0.2:443=1.1.1.1:5201", []Mapping{{"127.0.0.2:443", "1.1.1.1:5201"}}},
		{"[::1]:443=5201", []Mapping{{"[::1]:443", "5201"}}},
		{"500-500", []Mapping{{":500", "500"}}},
	}

	for _, tt := range tests {
		got, err := Parse([]string{tt.entry})
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", tt.entry, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Parse(%q) = %v, want %v", tt.entry, got, tt.want)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	entries := []string{
		"",
		"abc",
		"0",
		"65536",
		"600-443",
		"443-",
		"-443",
		"1-2-3",
		"443-600:abc",
		"443-600:0",
		"443=",
		"a=b=c",
		"127.0.0.2=5201",
		"127.0.0.2:0=5201",
		"0-10=5201",
	}

	for _, entry := range entries {
		if got, err := Parse([]string{entry}); err == nil {
			t.Errorf("Parse(%q) = %v, want error", entry, got)
		}
	}
}

func TestParseMultipleAndEmpty(t *testing.T) {
	got, err := Parse(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("Parse(nil) = %v, %v; want empty, nil", got, err)
	}

	got, err = Parse([]string{"443", "8000-8001=9000"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Mapping{{":443", "443"}, {":8000", "9000"}, {":8001", "9000"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	if _, err := Parse([]string{"443", "bad"}); err == nil {
		t.Fatal("expected error when any entry is invalid")
	}
}

package ids

import (
	"testing"
	"time"
)

func TestNewIsValidUniqueAndSortable(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := New()
		if !Valid(id) || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
	early := At(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	late := At(time.Date(2026, 1, 1, 0, 0, 0, int(time.Millisecond), time.UTC))
	if early[:10] >= late[:10] {
		t.Fatalf("ids not time-sortable: %s >= %s", early, late)
	}
}

func TestKnownEncoding(t *testing.T) {
	// All-zero time and randomness encodes to all zeros; max to 7ZZZ...
	if got := encode([16]byte{}); got != "00000000000000000000000000" {
		t.Fatalf("zero = %s", got)
	}
	var ones [16]byte
	for i := range ones {
		ones[i] = 0xff
	}
	if got := encode(ones); got != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max = %s", got)
	}
}

func TestValid(t *testing.T) {
	for _, bad := range []string{"", "01ARZ3NDEKTSV4RRFFQ69G5FA", "81ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAI", "01arz3ndektsv4rrffq69g5fav"} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
	if !Valid("01ARZ3NDEKTSV4RRFFQ69G5FAV") {
		t.Error("valid ULID rejected")
	}
}

package pwhash

import (
	"strings"
	"testing"
)

func TestHashAndCheck(t *testing.T) {
	h := Hash("correct horse")
	if !strings.HasPrefix(h, Prefix+"$argon2id$v=19$m=65536,t=2,p=1$") || !Valid(h) {
		t.Fatalf("hash %q", h)
	}
	if !Check(h, "correct horse") || Check(h, "correct horsE") || Check(h, "") {
		t.Fatal("Check gives the wrong answer")
	}
	if h == Hash("correct horse") {
		t.Fatal("two hashes of one password are equal: no salt")
	}
}

func TestCheckRefusesBadHashes(t *testing.T) {
	good := Hash("pw")
	for _, h := range []string{
		"", "pw", strings.TrimPrefix(good, Prefix),
		strings.Replace(good, "m=65536", "m=4194304", 1), // 4 GiB per check
		strings.Replace(good, "t=2", "t=0", 1),
		good + "$x",
	} {
		if Valid(h) || Check(h, "pw") {
			t.Errorf("%q is accepted", h)
		}
	}
	if d := Dummy(); !Valid(d) || d != Dummy() {
		t.Error("Dummy is not one valid hash")
	}
}

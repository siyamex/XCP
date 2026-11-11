package accounts

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

func TestAccountNotes(t *testing.T) {
	e := newEnv(t)
	a := e.create(t, "alice", "alice.example")
	b := e.create(t, "bob", "bob.example")
	e.waitStatus(t, a.ID, store.AccountActive)
	e.waitStatus(t, b.ID, store.AccountActive)

	n, err := e.svc.Note(ctx, e.admin, a.ID)
	if err != nil || n.Note != "" || len(n.Tags) != 0 || n.UpdatedAt != nil {
		t.Fatalf("no note yet: %+v %v", n, err)
	}
	n, err = e.svc.SetNote(ctx, client, e.admin, a.ID, "  Pays by invoice.  ", []string{"VIP", "late-payer", "vip", " "})
	if err != nil || n.Note != "Pays by invoice." || !slices.Equal(n.Tags, []string{"late-payer", "vip"}) || n.UpdatedBy != "root" || n.UpdatedAt == nil {
		t.Fatalf("%+v %v", n, err)
	}
	if got, _ := e.svc.Note(ctx, e.admin, a.ID); got.Note != n.Note || !slices.Equal(got.Tags, n.Tags) {
		t.Fatalf("read back: %+v", got)
	}

	for name, tags := range map[string][]string{
		"a space":  {"two words"},
		"too long": {strings.Repeat("a", MaxTagSize+1)},
		"too many": {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"},
	} {
		if _, err := e.svc.SetNote(ctx, client, e.admin, a.ID, "", tags); !errors.Is(err, validate.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.SetNote(ctx, client, e.admin, a.ID, strings.Repeat("x", MaxNote+1), nil); !errors.Is(err, validate.ErrValidation) {
		t.Errorf("a long note: %v", err)
	}
	if _, err := e.svc.SetNote(ctx, client, e.admin, "nope", "x", nil); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an unknown account: %v", err)
	}

	// Admins get the tags with the accounts and can filter by one.
	list, err := e.svc.List(ctx, e.admin, "", "")
	if err != nil || len(list) != 2 {
		t.Fatalf("%+v %v", list, err)
	}
	if got := WithTag(list, "VIP"); len(got) != 1 || got[0].Username != "alice" {
		t.Fatalf("with the tag: %+v", got)
	}
	if one, _ := e.svc.Get(ctx, e.admin, a.ID); !slices.Equal(one.Tags, []string{"late-payer", "vip"}) {
		t.Errorf("get: %+v", one.Tags)
	}

	// Nobody else: not a reseller, not the customer.
	rs := e.reseller(t, "rs", store.ResellerLimits{})
	if _, err := e.svc.Note(ctx, rs, a.ID); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a reseller reads: %v", err)
	}
	if _, err := e.svc.SetNote(ctx, client, rs, a.ID, "x", nil); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("a reseller writes: %v", err)
	}
	owned, err := e.svc.Create(ctx, client, rs, CreateInput{Username: "carol", Domain: "carol.example", PackageID: e.resellerPackage(t, rs, "p", nil), Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetNote(ctx, client, e.admin, owned.ID, "", []string{"watch"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.svc.List(ctx, rs, "", ""); len(list) != 1 || list[0].Tags != nil {
		t.Errorf("a reseller sees tags: %+v", list)
	}
	if one, _ := e.svc.Get(ctx, rs, owned.ID); one.Tags != nil {
		t.Errorf("a reseller sees tags: %+v", one.Tags)
	}

	// The note goes with the account.
	tr, err := e.svc.Terminate(ctx, client, e.admin, a.ID, "alice")
	if err != nil {
		t.Fatal(err)
	}
	e.waitJob(t, tr.JobID)
	if n, err := e.db.AccountNoteByID(ctx, a.ID); err != nil || n.Note != "" {
		t.Errorf("after termination: %+v %v", n, err)
	}
}

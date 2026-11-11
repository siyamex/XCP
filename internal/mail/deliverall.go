package mail

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
)

// Bounds of the report for all domains: it looks every domain up in public
// DNS, so it works on a few at a time and stops when the time is up.
const (
	reportWorkers = 8
	reportBudget  = 90 * time.Second
)

// CheckUnchecked is the status of a domain the report had no time for, or
// could not check.
const CheckUnchecked = "unchecked"

// DomainReport is one domain's line in the report for all domains.
type DomainReport struct {
	DomainID   string   `json:"domain_id"`
	Domain     string   `json:"domain"`
	AccountID  string   `json:"account_id"`
	Account    string   `json:"account"`
	Routing    string   `json:"routing"`
	Status     string   `json:"status"`   // the worst of its checks, or unchecked
	Problems   []string `json:"problems"` // names of the checks that are not ok
	Repairable bool     `json:"repairable"`
}

// DeliverabilityReport is the deliverability of every domain with mail.
type DeliverabilityReport struct {
	Items []DomainReport `json:"items"` // domains with problems first
	OK    int            `json:"ok"`
	// PTR is the server's own reverse-name check, the same for every domain;
	// it is not counted in the domains' problems.
	PTR Check `json:"ptr"`
}

func rank(status string) int {
	return slices.Index([]string{CheckOK, CheckUnchecked, CheckWarning, CheckError}, status)
}

// DeliverabilityAll runs the deliverability check for every domain with mail
// of every active account (admins, ADM-MAIL-07). Domains whose mail is
// handled elsewhere are left out.
func (s *Service) DeliverabilityAll(ctx context.Context, p *auth.Principal) (DeliverabilityReport, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return DeliverabilityReport{}, apperr.ErrForbidden
	}
	accts, err := s.db.ListAccounts(ctx, store.AccountFilter{Status: store.AccountActive})
	if err != nil {
		return DeliverabilityReport{}, err
	}
	rep := DeliverabilityReport{Items: []DomainReport{}}
	for _, a := range accts {
		doms, err := s.db.ListDomains(ctx, a.ID)
		if err != nil {
			return rep, err
		}
		for _, d := range doms {
			if strings.HasPrefix(d.Name, "*.") || d.Kind == store.DomainAlias {
				continue
			}
			rep.Items = append(rep.Items, DomainReport{
				DomainID: d.ID, Domain: d.Name, AccountID: a.ID, Account: a.Username, Status: CheckUnchecked, Problems: []string{},
			})
		}
	}

	lctx, cancel := context.WithTimeout(ctx, reportBudget)
	defer cancel()
	rep.PTR = s.checkPTR(lctx, s.serverIPs(lctx), s.server(ctx))
	var wg sync.WaitGroup
	next := make(chan *DomainReport)
	for range reportWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range next {
				res, err := s.Deliverability(lctx, p, it.DomainID)
				if err != nil {
					continue // no mail here, or the time is up: stays unchecked
				}
				it.Routing, it.Repairable, it.Status = res.Routing, res.Repairable, CheckOK
				for _, c := range res.Checks {
					if c.Name == "ptr" || c.Status == CheckOK {
						continue
					}
					it.Problems = append(it.Problems, c.Name)
					if rank(c.Status) > rank(it.Status) {
						it.Status = c.Status
					}
				}
			}
		}()
	}
	for i := range rep.Items {
		if lctx.Err() != nil {
			break
		}
		next <- &rep.Items[i]
	}
	close(next)
	wg.Wait()

	// A domain whose mail goes elsewhere has nothing to check here.
	rep.Items = slices.DeleteFunc(rep.Items, func(it DomainReport) bool { return it.Routing == store.MailRemote })
	slices.SortStableFunc(rep.Items, func(a, b DomainReport) int {
		if d := rank(b.Status) - rank(a.Status); d != 0 {
			return d
		}
		return strings.Compare(a.Domain, b.Domain)
	})
	for _, it := range rep.Items {
		if it.Status == CheckOK {
			rep.OK++
		}
	}
	return rep, nil
}

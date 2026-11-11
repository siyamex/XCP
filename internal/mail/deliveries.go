package mail

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// MaxDeliveries is how many deliveries one search returns.
const MaxDeliveries = 200

// Delivery is what the mail server did with a message for one recipient
// (USR-MAIL-10). xcp-logd records them from Postfix's log for two weeks.
type Delivery struct {
	At        time.Time `json:"at"`
	QueueID   string    `json:"queue_id"`
	Sender    string    `json:"sender"`
	Recipient string    `json:"recipient"`
	OrigTo    string    `json:"orig_to,omitempty"` // the address written to, if forwarded
	Status    string    `json:"status"`
	Relay     string    `json:"relay"`
	Detail    string    `json:"detail"`
	Size      int64     `json:"size"`
}

var deliveryStatuses = []string{store.DeliverySent, store.DeliveryDeferred, store.DeliveryBounced, store.DeliveryExpired, store.DeliveryRejected}

func (s *Service) deliveries(ctx context.Context, domains []string, search, status string) ([]Delivery, error) {
	search = strings.TrimSpace(search)
	if len(search) > 200 {
		return nil, badField("search", validate.CodeTooLong, "the search text can have 200 characters")
	}
	if status != "" && !slices.Contains(deliveryStatuses, status) {
		return nil, badField("status", validate.CodeFormat, "status must be sent, deferred, bounced, expired or rejected")
	}
	list, err := s.db.MailDeliveries(ctx, store.DeliveryFilter{Domains: domains, Search: search, Status: status, Limit: MaxDeliveries})
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0, len(list))
	for _, d := range list {
		out = append(out, Delivery{
			At: d.At, QueueID: d.QueueID, Sender: d.Sender, Recipient: d.Recipient, OrigTo: d.OrigTo,
			Status: d.Status, Relay: d.Relay, Detail: d.Detail, Size: d.Size,
		})
	}
	return out, nil
}

// Deliveries returns the newest deliveries of mail sent from or to an
// address at one of the account's domains.
func (s *Service) Deliveries(ctx context.Context, p *auth.Principal, accountID, search, status string) ([]Delivery, error) {
	a, _, err := s.access(ctx, p, accountID)
	if err != nil {
		return nil, err
	}
	doms, err := s.db.ListDomains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	names := []string{} // not nil: an account without domains sees nothing
	for _, d := range doms {
		if !strings.HasPrefix(d.Name, "*.") {
			names = append(names, d.Name)
		}
	}
	return s.deliveries(ctx, names, search, status)
}

// AllDeliveries returns the newest deliveries of the whole server (admins, ADM-MAIL-03).
func (s *Service) AllDeliveries(ctx context.Context, p *auth.Principal, search, status string) ([]Delivery, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return nil, apperr.ErrForbidden
	}
	return s.deliveries(ctx, nil, search, status)
}

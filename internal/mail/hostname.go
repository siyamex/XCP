package mail

import (
	"context"
	"strings"
)

// SetHostname changes the mail server's name (the host name was changed)
// and queues the job that applies it.
func (s *Service) SetHostname(ctx context.Context, hostname, createdBy string) (string, error) {
	st, err := s.load(ctx)
	if err != nil {
		return "", err
	}
	st.Hostname = strings.ToLower(hostname)
	if err := s.db.SetSetting(ctx, settingsKey, st); err != nil {
		return "", err
	}
	return s.EnqueueSettings(ctx, createdBy)
}

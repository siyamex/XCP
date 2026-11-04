package ssl

import "context"

// SetHostname changes the server's own name, the one AutoSSL gets the
// panel's certificate for (the host name was changed).
func (s *Service) SetHostname(ctx context.Context, hostname string) error {
	set, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	set.Hostname = hostname
	return s.db.SetSetting(ctx, settingsKey, set)
}

package backups

import (
	"context"
	"errors"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/auth"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// Schedule is the admin's backup schedule (ADM-BAK-01), in the server's time.
type Schedule struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // daily, weekly or monthly
	Hour      int    `json:"hour"`      // 0-23
	Weekday   int    `json:"weekday"`   // weekly: 0 (Sunday) - 6
	Day       int    `json:"day"`       // monthly: 1-28
	Keep      int    `json:"keep"`      // scheduled backups kept per account
	// DestinationID: copy every scheduled backup there (empty: nowhere).
	DestinationID string `json:"destination_id"`
	RemoteKeep    int    `json:"remote_keep"` // copies kept per account at the destination; 0: as many as Keep
}

const (
	scheduleKey = "backups.schedule"
	lastRunKey  = "backups.last_run"
)

var clientNone = auth.Client{}

// DefaultSchedule is off until the admin turns it on: backups need space.
var DefaultSchedule = Schedule{Frequency: "daily", Hour: 2, Day: 1, Keep: 7}

// Due reports whether the schedule starts backups in the hour of t.
func (s Schedule) Due(t time.Time) bool {
	if !s.Enabled || t.Hour() != s.Hour {
		return false
	}
	switch s.Frequency {
	case "weekly":
		return int(t.Weekday()) == s.Weekday
	case "monthly":
		return t.Day() == s.Day
	}
	return true
}

func (s *Service) schedule(ctx context.Context) (Schedule, error) {
	sched := DefaultSchedule
	err := s.db.GetSetting(ctx, scheduleKey, &sched)
	if errors.Is(err, store.ErrNotFound) {
		return DefaultSchedule, nil
	}
	return sched, err
}

// GetSchedule returns the backup schedule (admins only).
func (s *Service) GetSchedule(ctx context.Context, p *auth.Principal) (Schedule, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return Schedule{}, apperr.ErrForbidden
	}
	return s.schedule(ctx)
}

// SetSchedule changes the backup schedule (admins only).
func (s *Service) SetSchedule(ctx context.Context, c auth.Client, p *auth.Principal, in Schedule) (Schedule, error) {
	if p == nil || p.Login.Role != store.RoleAdmin {
		return Schedule{}, apperr.ErrForbidden
	}
	switch {
	case in.Frequency != "daily" && in.Frequency != "weekly" && in.Frequency != "monthly":
		return Schedule{}, badField("frequency", validate.CodeFormat, "daily, weekly or monthly")
	case in.Hour < 0 || in.Hour > 23:
		return Schedule{}, badField("hour", validate.CodeOutOfRange, "0 to 23")
	case in.Weekday < 0 || in.Weekday > 6:
		return Schedule{}, badField("weekday", validate.CodeOutOfRange, "0 (Sunday) to 6")
	case in.Day < 1 || in.Day > 28:
		return Schedule{}, badField("day", validate.CodeOutOfRange, "1 to 28, so every month has it")
	case in.Keep < 1 || in.Keep > 90:
		return Schedule{}, badField("keep", validate.CodeOutOfRange, "1 to 90")
	case in.RemoteKeep < 0 || in.RemoteKeep > 365:
		return Schedule{}, badField("remote_keep", validate.CodeOutOfRange, "0 (as many as kept here) to 365")
	}
	if in.DestinationID != "" {
		if _, err := s.db.BackupDestinationByID(ctx, in.DestinationID); err != nil {
			return Schedule{}, badField("destination_id", validate.CodeFormat, "no such destination")
		}
	}
	if err := s.db.SetSetting(ctx, scheduleKey, in); err != nil {
		return Schedule{}, err
	}
	return in, s.audit.Record(ctx, event(c, p, "backup.schedule.update", "", "", map[string]any{
		"enabled": in.Enabled, "frequency": in.Frequency, "hour": in.Hour, "weekday": in.Weekday, "day": in.Day, "keep": in.Keep,
		"destination_id": in.DestinationID, "remote_keep": in.RemoteKeep,
	}))
}

func badField(field, code, msg string) error {
	return &validate.Error{Field: field, Code: code, Message: msg}
}

package validate

import (
	"strings"

	"github.com/robfig/cron/v3"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// CronSchedule validates a standard 5-field crontab schedule or a descriptor
// such as @daily, and returns it with single spaces between fields.
// "@every" is rejected because crontab does not support it.
func CronSchedule(s string) (string, error) {
	s = strings.Join(strings.Fields(s), " ")
	switch {
	case s == "":
		return "", fail(CodeRequired, "schedule is required")
	case len(s) > 100:
		return "", fail(CodeTooLong, "schedule is too long")
	case strings.HasPrefix(s, "@every"):
		return "", fail(CodeFormat, "@every is not supported; use 5 fields like */15 * * * *")
	case strings.HasPrefix(s, "@reboot"):
		return "", fail(CodeFormat, "@reboot is not supported")
	}
	if _, err := cronParser.Parse(s); err != nil {
		return "", fail(CodeFormat, "invalid schedule: %v", err)
	}
	return s, nil
}

// MaxCronCommandLen bounds a crontab command line.
const MaxCronCommandLen = 1024

// CronCommand checks a cron command. Line breaks are refused because they
// would inject extra crontab lines. '%' is legal here; the crontab generator
// must escape it (crontab turns an unescaped % into a newline on stdin).
func CronCommand(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", fail(CodeRequired, "command is required")
	case len(s) > MaxCronCommandLen:
		return "", fail(CodeTooLong, "command must be at most %d bytes", MaxCronCommandLen)
	case strings.ContainsAny(s, "\x00\r\n"):
		return "", fail(CodeFormat, "command must be a single line")
	}
	return s, nil
}

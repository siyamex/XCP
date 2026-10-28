package plans

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/siyamex/XCP/internal/validate"
)

// Limits are a package's resource limits (08-data-model-and-api.md §2).
// A nil pointer means unlimited. Stored as JSON, so new limits can be added
// without a schema migration; unknown JSON keys are rejected on input.
type Limits struct {
	DiskMB       *int64   `json:"disk_mb"`
	Inodes       *int64   `json:"inodes"`
	BandwidthMB  *int64   `json:"bandwidth_mb"` // per month
	AddonDomains *int64   `json:"addon_domains"`
	Subdomains   *int64   `json:"subdomains"`
	Aliases      *int64   `json:"aliases"`
	Mailboxes    *int64   `json:"mailboxes"`
	MailboxMB    *int64   `json:"mailbox_mb"` // largest quota a single mailbox may get
	Forwarders   *int64   `json:"forwarders"`
	MailPerHour  *int64   `json:"mail_per_hour"`
	Databases    *int64   `json:"databases"`
	DBUsers      *int64   `json:"db_users"`
	FTPAccounts  *int64   `json:"ftp_accounts"`
	CronJobs     *int64   `json:"cron_jobs"`
	CPUPercent   *int64   `json:"cpu_percent"` // 100 = one full core
	MemoryMB     *int64   `json:"memory_mb"`
	Processes    *int64   `json:"processes"`
	IOMBps       *int64   `json:"io_mbps"`
	Shell        string   `json:"shell"`        // none, jailed, full
	PHPVersions  []string `json:"php_versions"` // empty: every version installed on the server
	DedicatedIP  bool     `json:"dedicated_ip"`
}

// Shell access levels.
const (
	ShellNone   = "none"
	ShellJailed = "jailed"
	ShellFull   = "full"
)

// MaxLimit bounds every numeric limit (about 9 PB in MB; far above any real value).
const MaxLimit = 1 << 33

var phpVersionRe = regexp.MustCompile(`^[5-9]\.[0-9]$`)

// Normalize fills defaults and validates. The error names the bad field.
func (l *Limits) Normalize() error {
	nums := map[string]*int64{
		"disk_mb": l.DiskMB, "inodes": l.Inodes, "bandwidth_mb": l.BandwidthMB,
		"addon_domains": l.AddonDomains, "subdomains": l.Subdomains, "aliases": l.Aliases,
		"mailboxes": l.Mailboxes, "mailbox_mb": l.MailboxMB, "forwarders": l.Forwarders,
		"mail_per_hour": l.MailPerHour, "databases": l.Databases, "db_users": l.DBUsers,
		"ftp_accounts": l.FTPAccounts, "cron_jobs": l.CronJobs, "cpu_percent": l.CPUPercent,
		"memory_mb": l.MemoryMB, "processes": l.Processes, "io_mbps": l.IOMBps,
	}
	for name, v := range nums {
		if v != nil && (*v < 0 || *v > MaxLimit) {
			return field("limits."+name, validate.CodeOutOfRange, fmt.Sprintf("must be between 0 and %d, or empty for unlimited", int64(MaxLimit)))
		}
	}
	if l.CPUPercent != nil && *l.CPUPercent > 0 && *l.CPUPercent < 5 {
		return field("limits.cpu_percent", validate.CodeOutOfRange, "below 5% a site cannot even start; use 0 to block or at least 5")
	}
	switch l.Shell {
	case "":
		l.Shell = ShellNone
	case ShellNone, ShellJailed, ShellFull:
	default:
		return field("limits.shell", validate.CodeFormat, "must be none, jailed or full")
	}
	for _, v := range l.PHPVersions {
		if !phpVersionRe.MatchString(v) {
			return field("limits.php_versions", validate.CodeFormat, fmt.Sprintf("%q is not a PHP version like 8.3", v))
		}
	}
	slices.Sort(l.PHPVersions)
	l.PHPVersions = slices.Compact(l.PHPVersions)
	if l.PHPVersions == nil {
		l.PHPVersions = []string{}
	}
	return nil
}

func field(name, code, msg string) error {
	return &validate.Error{Field: name, Code: code, Message: msg}
}

func ptr(v int64) *int64 { return &v }

// DefaultLimits are used for the "Default" package created on first start:
// a reasonable small shared-hosting plan.
func DefaultLimits() Limits {
	return Limits{
		DiskMB: ptr(10 * 1024), Inodes: ptr(250_000), BandwidthMB: ptr(100 * 1024),
		AddonDomains: ptr(5), Subdomains: ptr(20), Aliases: ptr(10),
		Mailboxes: ptr(25), MailboxMB: ptr(5 * 1024), Forwarders: ptr(50), MailPerHour: ptr(200),
		Databases: ptr(10), DBUsers: ptr(10), FTPAccounts: ptr(5), CronJobs: ptr(10),
		CPUPercent: ptr(100), MemoryMB: ptr(1024), Processes: ptr(100), IOMBps: ptr(50),
		Shell: ShellNone, PHPVersions: []string{},
	}
}

package agent

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/siyamex/XCP/internal/execx"
)

// Bounds of mailbox clean-up (USR-MAIL-02).
const (
	MaxCleanupDays = 3650
	maxFolders     = 1000
	maxFolderName  = 200
)

// MailFolder is one folder of a mailbox.
type MailFolder struct {
	Name     string
	Messages int64
	Bytes    int64
}

// CheckFolderName refuses folder names doveadm would read as a pattern or
// that hold control characters.
func CheckFolderName(name string) error {
	if name == "" || len(name) > maxFolderName || !utf8.ValidString(name) || strings.ContainsAny(name, "*%") {
		return invalid("%q is not a folder name", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return invalid("%q is not a folder name", name)
		}
	}
	return nil
}

// ownMailbox checks that address is a mailbox of the account.
func (m *Mail) ownMailbox(username, address string) error {
	if err := CheckAddress(address); err != nil {
		return err
	}
	if err := m.installed(); err != nil {
		return err
	}
	all, err := m.fragments("", nil)
	if err != nil {
		return err
	}
	for _, a := range all {
		if a.Username != username {
			continue
		}
		for _, d := range a.Domains {
			for _, b := range d.Mailboxes {
				if b.Local+"@"+d.Name == address {
					return nil
				}
			}
		}
	}
	return invalid("%s is not a mailbox of %s", address, username)
}

// parseFolderStatus reads "doveadm -f tab mailbox status ... messages vsize"
// output: a header line naming the columns, then one line per folder.
func parseFolderStatus(out []byte) ([]MailFolder, error) {
	lines := bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return []MailFolder{}, nil
	}
	head := strings.Split(string(lines[0]), "\t")
	col := func(name string) int { return slices.Index(head, name) }
	iName, iMsgs, iSize := col("mailbox"), col("messages"), col("vsize")
	if iName < 0 || iMsgs < 0 || iSize < 0 {
		return nil, fmt.Errorf("doveadm: unexpected columns %q", head)
	}
	out2 := []MailFolder{}
	for _, l := range lines[1:] {
		f := strings.Split(string(l), "\t")
		if len(f) != len(head) {
			continue
		}
		msgs, err1 := strconv.ParseInt(f[iMsgs], 10, 64)
		size, err2 := strconv.ParseInt(f[iSize], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out2 = append(out2, MailFolder{Name: f[iName], Messages: msgs, Bytes: size})
		if len(out2) >= maxFolders {
			break
		}
	}
	slices.SortFunc(out2, func(a, b MailFolder) int {
		if (a.Name == "INBOX") != (b.Name == "INBOX") {
			if a.Name == "INBOX" {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out2, nil
}

func (m *Mail) folders(ctx context.Context, address string, pattern string) ([]MailFolder, error) {
	res, err := m.Run.Run(ctx, execx.Cmd{
		Path: DoveadmPath, MaxOutput: 4 << 20,
		Args: []string{"-f", "tab", "mailbox", "status", "-u", address, "messages vsize", "--", pattern},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res.Stderr)))
	}
	return parseFolderStatus(res.Stdout)
}

// MailboxUsage lists a mailbox's folders with their messages and size.
func (m *Mail) MailboxUsage(ctx context.Context, username, address string) ([]MailFolder, error) {
	if err := m.ownMailbox(username, address); err != nil {
		return nil, err
	}
	return m.folders(ctx, address, "*")
}

// MailboxCleanup deletes the messages of one folder of a mailbox received
// before days days ago (IMAP's internal date: when the message arrived, or
// the date a mail program gave it when it copied it in), and reports how
// many went and how many bytes they took.
func (m *Mail) MailboxCleanup(ctx context.Context, username, address, folder string, days int) (int64, int64, error) {
	if days < 1 || days > MaxCleanupDays {
		return 0, 0, invalid("days must be 1 to %d", MaxCleanupDays)
	}
	if err := CheckFolderName(folder); err != nil {
		return 0, 0, err
	}
	if err := m.ownMailbox(username, address); err != nil {
		return 0, 0, err
	}
	before, err := m.folders(ctx, address, folder)
	if err != nil {
		return 0, 0, err
	}
	if len(before) != 1 || before[0].Name != folder {
		return 0, 0, invalid("%s has no folder %q", address, folder)
	}
	res, err := m.Run.Run(ctx, execx.Cmd{
		Path: DoveadmPath, Timeout: backupMaxRuntime, MaxOutput: 64 << 10,
		Args: []string{"expunge", "-u", address, "mailbox", folder, "before", strconv.Itoa(days) + "d"},
	})
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res.Stderr)))
	}
	after, err := m.folders(ctx, address, folder)
	if err != nil || len(after) != 1 {
		return 0, 0, err
	}
	return before[0].Messages - after[0].Messages, before[0].Bytes - after[0].Bytes, nil
}

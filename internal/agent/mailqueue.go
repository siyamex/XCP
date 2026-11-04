package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/execx"
)

// Postfix's queue tools (ADM-MAIL queue, ADR-0022).
const (
	PostqueuePath = "/usr/sbin/postqueue"
	PostsuperPath = "/usr/sbin/postsuper"
)

// MailQueue reads and manages Postfix's queue.
type MailQueue struct {
	Run *execx.Runner
}

// QueuedMail is one message in the queue.
type QueuedMail struct {
	ID         string
	Queue      string // active, deferred, hold, incoming
	Arrived    time.Time
	Size       int64
	Sender     string
	Recipients []QueuedRecipient
}

// QueuedRecipient is a recipient and why delivery waits.
type QueuedRecipient struct {
	Address string
	Reason  string
}

// MaxQueueList bounds a listing.
const MaxQueueList = 500

var queueIDRe = regexp.MustCompile(`^[0-9A-Za-z]{6,20}$`)

// CheckQueueIDs refuses what is not a queue id: ids go to a command line.
func CheckQueueIDs(ids []string) error {
	if len(ids) == 0 || len(ids) > MaxQueueList {
		return fmt.Errorf("1 to %d message ids", MaxQueueList)
	}
	for _, id := range ids {
		if !queueIDRe.MatchString(id) {
			return fmt.Errorf("%q is not a queue id", id)
		}
	}
	return nil
}

type postqueueJSON struct {
	QueueName   string `json:"queue_name"`
	QueueID     string `json:"queue_id"`
	ArrivalTime int64  `json:"arrival_time"`
	MessageSize int64  `json:"message_size"`
	Sender      string `json:"sender"`
	Recipients  []struct {
		Address     string `json:"address"`
		DelayReason string `json:"delay_reason"`
	} `json:"recipients"`
}

// ParseQueue reads `postqueue -j` output (one JSON object per line).
func ParseQueue(out []byte) ([]QueuedMail, error) {
	var res []QueuedMail
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m postqueueJSON
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, fmt.Errorf("postqueue output: %w", err)
		}
		q := QueuedMail{ID: m.QueueID, Queue: m.QueueName, Arrived: time.Unix(m.ArrivalTime, 0).UTC(), Size: m.MessageSize, Sender: m.Sender}
		for _, r := range m.Recipients {
			q.Recipients = append(q.Recipients, QueuedRecipient{Address: r.Address, Reason: strings.TrimSpace(r.DelayReason)})
		}
		res = append(res, q)
		if len(res) >= MaxQueueList {
			break
		}
	}
	return res, sc.Err()
}

// List returns the queue, newest first.
func (q *MailQueue) List(ctx context.Context) ([]QueuedMail, error) {
	res, err := q.Run.Run(ctx, execx.Cmd{Path: PostqueuePath, Args: []string{"-j"}, Timeout: 30 * time.Second, MaxOutput: 8 << 20})
	if err != nil {
		return nil, fmt.Errorf("postqueue: %w", err)
	}
	list, err := ParseQueue(res.Stdout)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	return list, nil
}

// Queue actions.
const (
	QueueFlushAll  = "flush_all"  // try every deferred message now
	QueueFlush     = "flush"      // try these now
	QueueDelete    = "delete"     // remove these
	QueueDeleteAll = "delete_all" // remove everything deferred
)

// Do runs a queue action; ids are needed for flush and delete only.
func (q *MailQueue) Do(ctx context.Context, action string, ids []string) error {
	var cmd execx.Cmd
	switch action {
	case QueueFlushAll:
		cmd = execx.Cmd{Path: PostqueuePath, Args: []string{"-f"}}
	case QueueFlush:
		if err := CheckQueueIDs(ids); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := q.Run.Run(ctx, execx.Cmd{Path: PostqueuePath, Args: []string{"-i", id}, Timeout: 30 * time.Second}); err != nil {
				return fmt.Errorf("flush %s: %w", id, err)
			}
		}
		return nil
	case QueueDelete:
		if err := CheckQueueIDs(ids); err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := q.Run.Run(ctx, execx.Cmd{Path: PostsuperPath, Args: []string{"-d", id}, Timeout: 30 * time.Second}); err != nil {
				return fmt.Errorf("delete %s: %w", id, err)
			}
		}
		return nil
	case QueueDeleteAll:
		cmd = execx.Cmd{Path: PostsuperPath, Args: []string{"-d", "ALL", "deferred"}}
	default:
		return fmt.Errorf("unknown queue action %q", action)
	}
	cmd.Timeout = 2 * time.Minute
	if _, err := q.Run.Run(ctx, cmd); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return nil
}

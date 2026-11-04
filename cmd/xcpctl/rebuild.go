package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
)

// rebuild asks the panel to apply everything again: every account, every
// DNS zone and the mail server's settings, from the panel's database. The
// jobs run in the background; follow them in the panel's task queue.
func rebuild(args []string, out io.Writer) error {
	if !slices.Contains(args, "--yes") && !slices.Contains(args, "-y") {
		return errors.New("rebuild applies every account, DNS zone and the mail settings again, which can take a while on a big server: run xcpctl rebuild --yes")
	}
	c, err := remoteClient()
	if err != nil {
		return err
	}
	var res struct {
		Queued map[string]int `json:"queued"`
	}
	if _, err := c.do("POST", "/server/rebuild", nil, &res); err != nil {
		return err
	}
	keys := make([]string, 0, len(res.Queued))
	for k := range res.Queued {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintln(out, "queued:")
	for _, k := range keys {
		fmt.Fprintf(out, "  %-10s %d\n", k, res.Queued[k])
	}
	fmt.Fprintln(out, "the jobs run in the background: see Task queue in the panel")
	return nil
}

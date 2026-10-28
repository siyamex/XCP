// Package plans manages packages (hosting plans) and feature lists
// (ADM-PKG-01/02). A package sets an account's limits; its feature list
// decides which panel features the account may use at all.
package plans

import "slices"

// Feature is a switchable part of the user panel. The UI shows a translated
// label from the key ("features.<key>"), grouped by Group.
type Feature struct {
	Key   string `json:"key"`
	Group string `json:"group"`
}

// Catalog lists every feature, in display order. Adding a feature here makes
// it available to feature lists; code that offers the feature must check
// the account's list (02-tech-stack-and-repo.md §4, "Feature flags").
var Catalog = []Feature{
	{"domains", "domains"},
	{"redirects", "domains"},
	{"dns_editor", "domains"},
	{"ssl", "domains"},
	{"email", "email"},
	{"webmail", "email"},
	{"spam_filter", "email"},
	{"mysql", "databases"},
	{"postgresql", "databases"},
	{"phpmyadmin", "databases"},
	{"file_manager", "files"},
	{"ftp", "files"},
	{"backups", "files"},
	{"php_settings", "web"},
	{"error_pages", "web"},
	{"hotlink_protection", "web"},
	{"ip_blocker", "web"},
	{"cron", "advanced"},
	{"ssh", "advanced"},
	{"terminal", "advanced"},
	{"git", "advanced"},
	{"apps", "advanced"},
	{"stats", "stats"},
	{"logs", "stats"},
}

// IsFeature reports whether key is in the catalog.
func IsFeature(key string) bool {
	return slices.ContainsFunc(Catalog, func(f Feature) bool { return f.Key == key })
}

// AllFeatures returns every feature key.
func AllFeatures() []string {
	out := make([]string, len(Catalog))
	for i, f := range Catalog {
		out[i] = f.Key
	}
	return out
}

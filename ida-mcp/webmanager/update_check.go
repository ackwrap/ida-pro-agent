package webmanager

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const latestReleaseAPI = "https://api.github.com/repos/ackwrap/ida-pro-agent/releases/latest"
const releasePagePrefix = "https://github.com/ackwrap/ida-pro-agent/releases/tag/"
const updateCheckInterval = 24 * time.Hour
const manualUpdateInterval = time.Minute

type productVersion struct {
	numbers    [3]uint64
	prerelease bool
}

func validVersionIdentifiers(text string, numericLeadingZero bool) bool {
	for _, part := range strings.Split(text, ".") {
		if part == "" {
			return false
		}
		numeric := true
		for _, c := range part {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
			numeric = numeric && c >= '0' && c <= '9'
		}
		if numericLeadingZero && numeric && len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}

func parseProductVersion(text string) (productVersion, bool) {
	var version productVersion
	if len(text) == 0 || len(text) > 128 {
		return version, false
	}
	text = strings.TrimPrefix(text, "v")
	if core, build, found := strings.Cut(text, "+"); found {
		if !validVersionIdentifiers(build, false) {
			return version, false
		}
		text = core
	}
	if core, pre, found := strings.Cut(text, "-"); found {
		if !validVersionIdentifiers(pre, true) {
			return version, false
		}
		version.prerelease = true
		text = core
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return version, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return version, false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return version, false
			}
		}
		n, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return version, false
		}
		version.numbers[i] = n
	}
	return version, true
}

func isStableReleaseTag(tag string) bool {
	version, ok := parseProductVersion(tag)
	return ok && !version.prerelease
}

func hasNewerRelease(installed, tag string) bool {
	current, currentOK := parseProductVersion(installed)
	latest, latestOK := parseProductVersion(tag)
	if !currentOK || !latestOK || latest.prerelease {
		return false
	}
	for i := range current.numbers {
		if latest.numbers[i] != current.numbers[i] {
			return latest.numbers[i] > current.numbers[i]
		}
	}
	return current.prerelease
}

type updateCache struct {
	Version    int    `json:"version"`
	CheckedAt  int64  `json:"checkedAt"`
	ReleaseTag string `json:"releaseTag"`
	Error      string `json:"error"`
}

func updateCheckDue(cache updateCache, now time.Time, manual bool) bool {
	interval := updateCheckInterval
	if manual {
		interval = manualUpdateInterval
	}
	return now.Unix() > 0 && (cache.CheckedAt <= 0 || cache.CheckedAt > now.Unix() || now.Unix()-cache.CheckedAt >= int64(interval/time.Second))
}

func decodeUpdateResponse(status int, body []byte, now time.Time, previous updateCache) updateCache {
	result := previous
	result.Version, result.CheckedAt = 1, now.Unix()
	result.Error = "Unable to check for updates. Try again later."
	if status == 403 || status == 429 {
		result.Error = "GitHub limited update requests. Try again later."
		return result
	}
	if status == 404 {
		result.Error = "No published stable release is available."
		return result
	}
	if status != 200 {
		return result
	}
	var release struct {
		Tag         string `json:"tag_name"`
		URL         string `json:"html_url"`
		Draft       *bool  `json:"draft"`
		Prerelease  *bool  `json:"prerelease"`
		PublishedAt string `json:"published_at"`
	}
	result.Error = "GitHub returned invalid release information."
	if err := json.Unmarshal(body, &release); err != nil || release.Draft == nil || *release.Draft || release.Prerelease == nil || *release.Prerelease || release.PublishedAt == "" || !isStableReleaseTag(release.Tag) || release.URL != releasePagePrefix+release.Tag {
		return result
	}
	result.ReleaseTag, result.Error = release.Tag, ""
	return result
}

func updateStatusText(installed string, cache updateCache) string {
	status := fmt.Sprintf("Installed version: %s. ", installed)
	if hasNewerRelease(installed, cache.ReleaseTag) {
		status += "Update available: " + cache.ReleaseTag + "."
	} else if cache.ReleaseTag != "" && cache.Error == "" {
		status += "You have the latest stable version."
	} else if cache.CheckedAt == 0 {
		status += "Updates have not been checked yet."
	}
	if cache.Error != "" {
		status += " " + cache.Error
	}
	return status
}

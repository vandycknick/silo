package commands

import (
	"fmt"
	"time"
)

// Memory follows the CLI's MiB hardware display, with whole GiB abbreviated to G.
func humanMemory(bytes uint64) string {
	mib := bytes / (1024 * 1024)
	if mib%1024 == 0 {
		return fmt.Sprintf("%dG", mib/1024)
	}
	return fmt.Sprintf("%dM", mib)
}

func humanDisk(bytes uint64) string {
	unit, suffix := uint64(1024*1024), "MiB"
	if bytes >= 1024*1024*1024 {
		unit, suffix = 1024*1024*1024, "GiB"
	} else if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	whole, remainder := bytes/unit, bytes%unit
	if remainder == 0 {
		return fmt.Sprintf("%d%s", whole, suffix)
	}
	hundredths := (remainder*100 + unit/2) / unit
	if hundredths == 100 {
		return fmt.Sprintf("%d%s", whole+1, suffix)
	}
	if hundredths%10 == 0 {
		return fmt.Sprintf("%d.%d%s", whole, hundredths/10, suffix)
	}
	return fmt.Sprintf("%d.%02d%s", whole, hundredths, suffix)
}

func absoluteTime(created time.Time) string {
	if created.IsZero() {
		return "N/A"
	}
	return created.UTC().Format("2006-01-02 15:04:05 UTC")
}

// Use Unix seconds, as the CLI does, rather than duration's bounded nanoseconds.
func relativeTime(created, now time.Time) string {
	if created.IsZero() || created.Unix() == 0 {
		return "N/A"
	}
	seconds := now.Unix() - created.Unix()
	if seconds < 5 {
		return "Less than a second ago"
	}
	if seconds < 60 {
		return fmt.Sprintf("%d seconds ago", seconds)
	}
	minutes := seconds / 60
	if minutes == 1 {
		return "About a minute ago"
	}
	if minutes < 60 {
		return fmt.Sprintf("%d minutes ago", minutes)
	}
	hours := minutes / 60
	if hours == 1 {
		return "About an hour ago"
	}
	if hours < 48 {
		return fmt.Sprintf("%d hours ago", hours)
	}
	days := hours / 24
	if days < 14 {
		return fmt.Sprintf("%d days ago", days)
	}
	weeks := days / 7
	if weeks < 8 {
		return fmt.Sprintf("%d weeks ago", weeks)
	}
	months := days / 30
	if months < 12 {
		return fmt.Sprintf("%d months ago", months)
	}
	return fmt.Sprintf("%d years ago", days/365)
}

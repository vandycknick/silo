package commands

import (
	"testing"
	"time"
)

func TestHumanSizesMatchCLI(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0G"}, {4 * 1024 * 1024 * 1024, "4G"}, {1536 * 1024 * 1024, "1536M"}, {512 * 1024 * 1024, "512M"},
	} {
		if got := humanMemory(tc.bytes); got != tc.want {
			t.Fatalf("memory %d: %s != %s", tc.bytes, got, tc.want)
		}
	}
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0B"}, {123, "123B"}, {1024*1024 - 1, "1048575B"}, {512 * 1024 * 1024, "512MiB"}, {64 * 1024 * 1024 * 1024, "64GiB"}, {200_000_000_000, "186.26GiB"}, {1536 * 1024 * 1024, "1.5GiB"}, {1024*1024 + 10486, "1.01MiB"}, {2*1024*1024 - 1, "2MiB"}, {^uint64(0), "17179869184GiB"},
	} {
		if got := humanDisk(tc.bytes); got != tc.want {
			t.Fatalf("disk %d: %s != %s", tc.bytes, got, tc.want)
		}
	}
}

func TestRelativeTimeCLIBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		seconds int64
		want    string
	}{
		{-60, "Less than a second ago"}, {0, "Less than a second ago"}, {4, "Less than a second ago"}, {5, "5 seconds ago"}, {59, "59 seconds ago"}, {60, "About a minute ago"}, {119, "About a minute ago"}, {120, "2 minutes ago"}, {3599, "59 minutes ago"}, {3600, "About an hour ago"}, {7199, "About an hour ago"}, {7200, "2 hours ago"}, {48*3600 - 1, "47 hours ago"}, {48 * 3600, "2 days ago"}, {14*86400 - 1, "13 days ago"}, {14 * 86400, "2 weeks ago"}, {56*86400 - 1, "7 weeks ago"}, {56 * 86400, "1 months ago"}, {360*86400 - 1, "11 months ago"}, {360 * 86400, "0 years ago"}, {365 * 86400, "1 years ago"}, {730 * 86400, "2 years ago"},
	} {
		if got := relativeTime(time.Unix(now.Unix()-tc.seconds, 0), now); got != tc.want {
			t.Fatalf("age %d: %s != %s", tc.seconds, got, tc.want)
		}
	}
	for _, created := range []time.Time{{}, time.Unix(0, 0)} {
		if got := relativeTime(created, now); got != "N/A" {
			t.Fatal(got)
		}
	}
	if got := absoluteTime(now.In(time.FixedZone("offset", 7200))); got != "2026-10-02 12:00:00 UTC" {
		t.Fatal(got)
	}
	if got := absoluteTime(time.Time{}); got != "N/A" {
		t.Fatal(got)
	}
}

package main

import (
	"testing"
	"time"

	appconfig "github.com/amdzy/NetWarden/internal/config"
)

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02 15:04", value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestScheduleActiveSameDayWindow(t *testing.T) {
	schedule := appconfig.Schedule{Start: "09:00", End: "17:00", Days: []int{1, 2, 3, 4, 5}}
	cases := []struct {
		when string
		want bool
	}{
		{"2026-10-12 08:59", false},
		{"2026-10-12 09:00", true},
		{"2026-10-12 16:59", true},
		{"2026-10-12 17:00", false},
		{"2026-10-13 10:00", true},
		{"2026-10-11 10:00", false}, // Sunday is not selected
	}
	for _, testCase := range cases {
		if got := scheduleActive(schedule, at(t, testCase.when)); got != testCase.want {
			t.Fatalf("scheduleActive(%s) = %t, want %t", testCase.when, got, testCase.want)
		}
	}
}

func TestScheduleActiveWrapsMidnight(t *testing.T) {
	schedule := appconfig.Schedule{Start: "22:00", End: "06:00", Days: []int{5}} // Friday 22:00 -> Saturday 06:00
	cases := []struct {
		when string
		want bool
	}{
		{"2026-10-16 21:59", false}, // Friday before
		{"2026-10-16 22:00", true},  // Friday start
		{"2026-10-17 05:59", true},  // Saturday tail
		{"2026-10-17 06:00", false}, // Saturday after
		{"2026-10-16 03:00", false}, // Friday morning is not in the window
		{"2026-10-15 23:00", false}, // Thursday is not a start day
	}
	for _, testCase := range cases {
		if got := scheduleActive(schedule, at(t, testCase.when)); got != testCase.want {
			t.Fatalf("scheduleActive(%s) = %t, want %t", testCase.when, got, testCase.want)
		}
	}
}

func TestScheduleActiveRejectsInvalidWindows(t *testing.T) {
	if scheduleActive(appconfig.Schedule{Start: "09:00", End: "09:00", Days: []int{1}}, at(t, "2026-10-12 09:30")) {
		t.Fatal("zero-length window must never be active")
	}
	if scheduleActive(appconfig.Schedule{Start: "bogus", End: "10:00", Days: []int{1}}, at(t, "2026-10-12 09:30")) {
		t.Fatal("invalid start must not be active")
	}
}

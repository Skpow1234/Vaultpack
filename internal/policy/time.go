package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// contains reports whether t falls in the closed [From, To] window in the
// configured timezone. If From > To, the window wraps over midnight (e.g.
// "22:00" .. "06:00").
func (w *TimeWindow) contains(t time.Time) (bool, error) {
	tz := w.Timezone
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return false, fmt.Errorf("time_window.timezone %q: %w", tz, err)
	}
	local := t.In(loc)
	fromMin, err := parseHHMM(w.From)
	if err != nil {
		return false, err
	}
	toMin, err := parseHHMM(w.To)
	if err != nil {
		return false, err
	}
	cur := local.Hour()*60 + local.Minute()
	if fromMin <= toMin {
		return cur >= fromMin && cur <= toMin, nil
	}
	// Wrapped window: e.g. 22:00 .. 06:00.
	return cur >= fromMin || cur <= toMin, nil
}

// parseHHMM converts "HH:MM" to minutes-since-midnight.
func parseHHMM(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("time %q: want HH:MM", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("time %q: invalid hour", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("time %q: invalid minute", s)
	}
	return h*60 + m, nil
}

func isWeekday(name string) bool {
	switch strings.ToLower(name) {
	case "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday":
		return true
	}
	return false
}

package agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

var allowedUpdateDays = map[string]time.Weekday{
	"Sun": time.Sunday,
	"Mon": time.Monday,
	"Tue": time.Tuesday,
	"Wed": time.Wednesday,
	"Thu": time.Thursday,
	"Fri": time.Friday,
	"Sat": time.Saturday,
}

type updateWindow struct {
	days      map[time.Weekday]bool
	startMins int
	endMins   int
}

func IsWithinUpdateWindow(now time.Time, window string) (bool, error) {
	trimmed := strings.TrimSpace(window)
	if trimmed == "" {
		return true, nil
	}

	parsed, err := parseUpdateWindow(trimmed)
	if err != nil {
		return false, err
	}

	if !parsed.days[now.Weekday()] {
		return false, nil
	}

	nowMins := now.Hour()*60 + now.Minute()
	return nowMins >= parsed.startMins && nowMins < parsed.endMins, nil
}

func parseUpdateWindow(window string) (updateWindow, error) {
	parts := strings.Split(window, "|")
	if len(parts) != 2 {
		return updateWindow{}, fmt.Errorf("invalid update_window format")
	}

	if !strings.HasPrefix(parts[0], "days=") || !strings.HasPrefix(parts[1], "time=") {
		return updateWindow{}, fmt.Errorf("invalid update_window format")
	}

	daysPart := strings.TrimPrefix(parts[0], "days=")
	timePart := strings.TrimPrefix(parts[1], "time=")
	if daysPart == "" || timePart == "" {
		return updateWindow{}, fmt.Errorf("invalid update_window format")
	}

	days, err := parseUpdateDays(daysPart)
	if err != nil {
		return updateWindow{}, err
	}

	start, end, err := parseUpdateTimeRange(timePart)
	if err != nil {
		return updateWindow{}, err
	}

	return updateWindow{
		days:      days,
		startMins: start,
		endMins:   end,
	}, nil
}

func parseUpdateDays(daysPart string) (map[time.Weekday]bool, error) {
	dayValues := strings.Split(daysPart, ",")
	if len(dayValues) == 0 {
		return nil, fmt.Errorf("invalid update_window days")
	}

	allowed := make(map[time.Weekday]bool, len(dayValues))
	for _, dayValue := range dayValues {
		day, ok := allowedUpdateDays[dayValue]
		if !ok {
			return nil, fmt.Errorf("invalid update_window day %q", dayValue)
		}
		allowed[day] = true
	}
	return allowed, nil
}

func parseUpdateTimeRange(timePart string) (int, int, error) {
	timeValues := strings.Split(timePart, "-")
	if len(timeValues) != 2 {
		return 0, 0, fmt.Errorf("invalid update_window time range")
	}

	start, err := parseHHMM(timeValues[0])
	if err != nil {
		return 0, 0, err
	}
	end, err := parseHHMM(timeValues[1])
	if err != nil {
		return 0, 0, err
	}
	if end <= start {
		return 0, 0, fmt.Errorf("invalid update_window time range")
	}

	return start, end, nil
}

func parseHHMM(value string) (int, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, fmt.Errorf("invalid update_window time value %q", value)
	}

	hours, err := strconv.Atoi(value[:2])
	if err != nil {
		return 0, fmt.Errorf("invalid update_window time value %q", value)
	}
	minutes, err := strconv.Atoi(value[3:])
	if err != nil {
		return 0, fmt.Errorf("invalid update_window time value %q", value)
	}
	if hours < 0 || hours > 23 || minutes < 0 || minutes > 59 {
		return 0, fmt.Errorf("invalid update_window time value %q", value)
	}

	return hours*60 + minutes, nil
}

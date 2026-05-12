package utils

import (
	"os"
	"time"
)

func TodayInLocation() time.Time {
	loc, err := time.LoadLocation(os.Getenv("LOCATION"))
	if err != nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
}
func TimeNowInLocation() time.Time {
	loc, err := time.LoadLocation(os.Getenv("Location"))
	if err != nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	return now
}

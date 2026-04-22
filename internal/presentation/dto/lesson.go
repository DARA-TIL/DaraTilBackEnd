package dto

import (
	"time"
)

type Lesson struct {
	ID            uint           `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	ImageUrl      string         `json:"imageUrl"`
	Author        string         `json:"author"`
	Reward        int            `json:"reward"`
	RequiredLevel int            `json:"requiredLevel"`
	LessonStatus  string         `json:"lessonStatus"`
	Blocks        []LessonBlock  `json:"blocks"`
	Results       []LessonResult `json:"results"`
	BestResult    *LessonResult  `json:"bestResult,omitempty"`
}

type LessonBlock struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	ContentUrl  string `json:"contentUrl"`
	ContentText string `json:"contentText"`
	LessonID    uint   `json:"lessonId"`
	Position    int    `json:"position"`
}

type UpdateLesson struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	ImageUrl      *string `json:"imageUrl,omitempty"`
	Author        *string `json:"author,omitempty"`
	Reward        *int    `json:"reward,omitempty"`
	RequiredLevel *int    `json:"requiredLevel,omitempty"`
}

type UpdateLessonBlock struct {
	Name        *string `json:"name,omitempty"`
	ContentType *string `json:"contentType,omitempty"`
	ContentUrl  *string `json:"contentUrl,omitempty"`
	ContentText *string `json:"contentText,omitempty"`
	Position    *int    `json:"position,omitempty"`
	LessonID    *uint   `json:"lessonID"`
}
type LessonResult struct {
	ID       uint `json:"id"`
	UserID   uint `json:"userId"`
	TestID   uint `json:"testId"`
	LessonID uint `json:"lessonId"`
	Result   uint `json:"result"`
	Pass     bool `json:"pass"`
	PassTime time.Time
}

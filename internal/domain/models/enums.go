package models

type Language string

const (
	KZ Language = "KZ"
	EN Language = "EN"
	RU Language = "RU"
)

type ActionTrigger string

const (
	EventStreak      ActionTrigger = "streak"
	EventActivity    ActionTrigger = "activity"
	EventAchievement ActionTrigger = "achievement"
)

type Actions string

const (
	Lesson_completed        Actions = "lesson_completed"
	Folklore_liked          Actions = "folklore_liked"
	Folklore_disliked       Actions = "folklore_disliked"
	Folklore_readed         Actions = "folklore_readed"
	Level_upgraded          Actions = "level_upgraded"
	Region_slang_readed     Actions = "region_slang_readed"
	Region_tradition_readed Actions = "region_tradition_readed"
)

type EventEntityType string

const (
	FolkloreEntityType  EventEntityType = "folklore"
	LessonEntityType    EventEntityType = "lesson"
	UserEntityType      EventEntityType = "user"
	SlangEntityType     EventEntityType = "slang"
	TraditionEntityType EventEntityType = "tradition"
)

package models

type Language string

const (
	KZ Language = "KZ"
	EN Language = "EN"
	RU Language = "RU"
)

type NotificationTrigger string

const (
	StreakIncrease NotificationTrigger = "streakIncrease"
	StreakReset    NotificationTrigger = "streakReset"
	Achieved       NotificationTrigger = "achieved"
	UserLogOut     NotificationTrigger = "userLogOut"
)

type ActionTrigger string

const (
	EventStreak      ActionTrigger = "streak"
	EventActivity    ActionTrigger = "activity"
	EventAchievement ActionTrigger = "achievement"
	StatsImprovement ActionTrigger = "stats-improvement"
	TimeEventTrigger ActionTrigger = "time-event"
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
	Word_Learned            Actions = "word_learned"
)

type EventType string

type EventEntityType string

const (
	FolkloreEntityType  EventEntityType = "folklore"
	LessonEntityType    EventEntityType = "lesson"
	UserEntityType      EventEntityType = "user"
	SlangEntityType     EventEntityType = "slang"
	TraditionEntityType EventEntityType = "tradition"
)

type TimeEventStatus string

const (
	Started  TimeEventStatus = "started"
	Ended    TimeEventStatus = "ended"
	Waiting  TimeEventStatus = "waiting"
	Canceled TimeEventStatus = "canceled"
)

type AiChatEventTypes string

const (
	EventSendMessage          = "ai_chat_send_message"
	EventUserMessageSaved     = "ai_chat_user_message_saved"
	EventAssistantTypingEnded = "ai_chat_assistant_typing_ended"
	EventAssistantTyping      = "ai_chat_assistant_typing"
	EventError                = "ai_chat_error"
)

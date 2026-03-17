package models

type Achievement struct {
	ID          uint
	Name        string
	Description string
	Action      Actions
	Quantity    uint
	IconURL     string

	UserAchievements []UserAchievement
}
type UserAchievement struct {
	ID            uint
	UserID        uint
	AchievementID uint
	Quantity      uint
	Achieved      bool
}

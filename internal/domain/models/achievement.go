package models

type Achievement struct {
	ID          uint
	Name        string
	Description string
	Action      string
	Quantity    uint
	IconURL     string
}
type UserAchievement struct {
	ID            uint
	UserID        uint
	AchievementID uint
	Quantity      uint
	Achieved      bool
}

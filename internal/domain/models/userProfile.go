package models

type UserProfile struct {
	UserID             uint
	PinnedAchievements []Achievement
	LessonsCompleted   int
	WordsLearned       int
	User               User
}

type CreateUserProfile struct {
	UserID uint
}
type UserProfileUpdate struct {
	UserID               uint
	PinnedAchievementIDS []uint
}

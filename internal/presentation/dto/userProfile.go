package dto

type UserProfile struct {
	UserID             uint          `json:"userId"`
	PinnedAchievements []Achievement `json:"pinnedAchievements"`
	LessonsCompleted   int           `json:"lessonsCompleted"`
	WordsLearned       int           `json:"wordsLearned"`
	User               User          `json:"user"`
}

type CreateUserProfile struct {
	UserID uint `json:"userId"`
}
type UserProfileUpdate struct {
	PinnedAchievementIDS []uint `json:"pinnedAchievementIds"`
}

package dto

type FinishLessonResults struct {
	IsImproved     bool `json:"isImproved"`
	IsLvlUp        bool `json:"isLvlUp"`
	XpGained       int  `json:"xpGained,omitempty"`
	PrevBestResult uint `json:"prevBestResult,omitempty"`
	MaxXp          int  `json:"maxXp,omitempty"`
	PrevXp         int  `json:"prevXp,omitempty"`
	PrevLevel      int  `json:"prevLevel,omitempty"`
	CurrentXp      int  `json:"currentXp,omitempty"`
	XpForNextLevel int  `json:"xpForNextLevel,omitempty"`
	CurrentLevel   int  `json:"currentLevel,omitempty"`
}
type GetFolkloreResponse struct {
	Folklore FolkloreDTO `json:"folklore"`
	Streak   string      `json:"streak"`
}
type GetSlangResponse struct {
	Slang  RegionSlang `json:"regionSlang"`
	Streak string      `json:"streak"`
}
type GetTraditionResponse struct {
	Tradition RegionTraditions `json:"regionTradition"`
	Streak    string           `json:"streak"`
}
type LikeFolkloreResponse struct {
	Folklore FolkloreDTO `json:"folklore"`
	Liked    bool        `json:"liked"`
	Streak   string      `json:"streak"`
}

type RefreshTokenResponse struct {
	User        UserClaims `json:"user"`
	AccessToken string     `json:"accessToken"`
	Status      string     `json:"status"`
	Streak      string     `json:"streak"`
}
type FinishLessonResponse struct {
	LessonResult LessonResult         `json:"lessonResult"`
	Progress     *FinishLessonResults `json:"progress"`
	Streak       string               `json:"streak"`
}
type LoginResponse struct {
	User        User   `json:"user"`
	AccessToken string `json:"accessToken"`
	Streak      string `json:"streak"`
}
type GetMeResponse struct {
	User   User   `json:"user"`
	Streak string `json:"streak"`
}

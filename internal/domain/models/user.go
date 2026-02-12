package models

type User struct {
	ID           uint
	Username     string
	Email        string
	Password     string
	Avatar       string
	Role         string
	AuthProvider string
	Progress     UserProgress
	Tokens       []Token
}

type UserProgress struct {
	ID             uint
	UserID         uint
	Level          int
	XpTotal        int
	XpForNextLevel int
}

type UserUpdatableFields struct {
	Username *string
	Avatar   *string
	Role     *string
	Password *string
}
type LvlRet struct {
	PrevLevel int
	PrevXp    int
	IsLvlUp   bool
	User      *User
	Err       error
}

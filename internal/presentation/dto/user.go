package dto

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type User struct {
	ID           uint         `json:"id"`
	Username     string       `json:"username"`
	Email        string       `json:"email"`
	Password     string       `json:"password"`
	Avatar       string       `json:"avatar"`
	Role         string       `json:"role"`
	AuthProvider string       `json:"authProvider"`
	Progress     UserProgress `json:"progress"`
}

type UserProgress struct {
	ID             uint `json:"id"`
	UserID         uint `json:"userID"`
	Level          int  `json:"level"`
	XpTotal        int  `json:"XpTotal"`
	XpForNextLevel int  `json:"XpForNextLevel"`
}
type UserUpdatableFields struct {
	Username *string `json:"username"`
	Avatar   *string `json:"avatar"`
	Role     *string `json:"role"`
	Password *string `json:"password"`
}

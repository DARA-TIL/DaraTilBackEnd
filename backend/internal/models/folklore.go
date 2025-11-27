package models

import "gorm.io/gorm"

type Folklore struct {
	gorm.Model
	Type       string `json:"type" gorm:"not null"`
	Content    string `json:"content" gorm:"not null"`
	Author     string `json:"author" gorm:"not null"`
	ImageUrl   string `json:"imageUrl"`
	IsApproved bool   `json:"isApproved" gorm:"not null"`
	Likes      int    `json:"likes" gorm:"not null"`
}

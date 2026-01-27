package gormModels

import "gorm.io/gorm"

type Folklore struct {
	gorm.Model
	Type         string `gorm:"not null"`
	Author       string `gorm:"not null"`
	Region       string `gorm:"not null"`
	Content      string `gorm:""`
	Name         string `gorm:""`
	MediaUrl     string
	ImageUrl     string
	LikesCount   int                   `gorm:"default:0"`
	Likes        []FolkloreLike        `gorm:"constraint:OnDelete:CASCADE;"`
	Translations []FolkloreTranslation `gorm:"constraint:OnDelete:CASCADE;"`
}

type FolkloreTranslation struct {
	gorm.Model
	FolkloreID  uint   `gorm:"not null"`
	Language    string `gorm:"not null"`
	Name        string `gorm:"not null"`
	Content     string `gorm:"not null"`
	Explanation string `gorm:"not null"`
}

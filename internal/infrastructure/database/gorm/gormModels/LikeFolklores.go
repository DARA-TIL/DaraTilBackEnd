package gormModels

import (
	"gorm.io/gorm"
)

type FolkloreLike struct {
	gorm.Model

	UserID     uint `gorm:"not null;uniqueIndex:user_folklore_idx"`
	FolkloreID uint `gorm:"not null;uniqueIndex:user_folklore_idx"`

	// связи
	User     User     `gorm:"foreignKey:UserID; OnDelete:CASCADE;"`
	Folklore Folklore `gorm:"foreignKey:FolkloreID; OnDelete:CASCADE;"`
}

package lesson

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.RouterGroup, h *LessonHandler) {
	router.POST("/create", h.CreateLesson)
	router.GET("/getAll", h.GetLessons)
	router.GET("/getById/:id", h.GetLessonByID)
	router.PATCH("/update/:id", h.UpdateLesson)
	router.DELETE("/delete/:id", h.DeleteLesson)

	router.POST("/finish", h.FinishLesson)

	// Lesson Blocks
	router.POST("/createBlock", h.CreateBlock)
	router.PATCH("/updateBlock/:id", h.UpdateBlock)
	router.DELETE("/deleteBlock/:id", h.DeleteBlock)
}

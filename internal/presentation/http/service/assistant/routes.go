package assistant

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.RouterGroup, handler *Assistant) {
	router.POST("/explainWord", handler.ExplainWord)
}

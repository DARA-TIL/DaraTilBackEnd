package actionRule

import (
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *ActionRuleHandler) {
	r.POST("/create", h.Create)
	r.POST("/createMulti", h.CreateMulti)
	r.GET("/getAll", h.GetAll)
	r.GET("/get/:action", h.GetByAction)
	r.PATCH("/update", h.Update)
	r.DELETE("/delete/:action", h.Delete)
}

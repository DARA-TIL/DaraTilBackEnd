package subscription

import (
	"github.com/gin-gonic/gin"
)

func RegisterSubscriptionRoutes(r *gin.RouterGroup, subscriptionHandler *SubscriptionHandler) {
	{
		r.POST("", subscriptionHandler.Create)
		r.GET("", subscriptionHandler.List)
		r.GET("/:id", subscriptionHandler.GetByID)
		r.PATCH("/:id", subscriptionHandler.Update)
		r.DELETE("/:id", subscriptionHandler.Delete)

		r.GET("/users/:id/active", subscriptionHandler.GetActiveByUserID)
		r.PATCH("/:id/cancel", subscriptionHandler.Cancel)
		r.PATCH("/:id/expire", subscriptionHandler.Expire)
	}
}
func RegisterSubscriptionPlanRoutes(r *gin.RouterGroup, subscriptionPlanHandler *SubscriptionPlanHandler) {
	r.POST("", subscriptionPlanHandler.Create)
	r.GET("", subscriptionPlanHandler.List)
	r.GET("/:id", subscriptionPlanHandler.GetByID)
	r.PATCH("/:id", subscriptionPlanHandler.Update)
	r.DELETE("/:id", subscriptionPlanHandler.Delete)
}

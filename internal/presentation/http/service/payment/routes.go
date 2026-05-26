package payment

import (
	"github.com/gin-gonic/gin"
)

func RegisterPaymentRoutes(
	router *gin.RouterGroup,
	handler *PaymentHandler,
) {
	{
		router.POST("", handler.Create)
		router.GET("/:id/mock-pay", handler.MockPay)
	}
}

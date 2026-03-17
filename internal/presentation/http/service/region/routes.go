package region

import (
	"DaraTilBackendV2/internal/presentation/http/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.RouterGroup, h *RegionHandler) {
	r.POST("/create", middleware.RequireRole("admin"), h.CreateRegion)
	r.POST("/createAll", middleware.RequireRole("admin"), h.CreateAllRegions)
	r.GET("/getAll", h.GetAllRegion)
	r.GET("/getById/:id", h.GetRegionByID)
	r.GET("/getByCode/:code", h.GetByCode)
	r.PATCH("/update", middleware.RequireRole("admin"), h.UpdateRegion)
	r.DELETE("/delete/:id", middleware.RequireRole("admin"), h.DeleteRegion)

	// translations
	r.POST("/translation/create", middleware.RequireRole("admin"), h.CreateRegionTranslation)
	r.GET("/translation/getById/:id", h.GetRegionTranslationByID)
	r.GET("/:id/translations", h.GetTranslationsByRegionID)
	r.PATCH("/translation/update", middleware.RequireRole("admin"), h.UpdateRegionTranslation)
	r.DELETE("/translation/delete/:id", middleware.RequireRole("admin"), h.DeleteRegionTranslation)
}
func RegisterSlangRoutes(r *gin.RouterGroup, h *RegionSlangHandler) {
	r.POST("/slang/create", middleware.RequireRole("admin"), h.CreateRegionSlang)
	r.GET("/slang/getById/:id", h.GetRegionSlangByID)
	r.GET("/:id/slang", h.GetSlangByRegionID)
	r.PATCH("/slang/update", middleware.RequireRole("admin"), h.UpdateRegionSlang)
	r.DELETE("/slang/delete/:id", middleware.RequireRole("admin"), h.DeleteRegionSlang)

	// translations
	r.POST("/slang/translation/create", middleware.RequireRole("admin"), h.CreateRegionSlangTranslation)
	r.GET("/slang/translation/getById/:id", h.GetRegionSlangTranslationByID)
	r.GET("/slang/:id/translations", h.GetSlangTranslationsBySlangID)
	r.PATCH("/slang/translation/update", middleware.RequireRole("admin"), h.UpdateRegionSlangTranslation)
	r.DELETE("/slang/translation/delete/:id", middleware.RequireRole("admin"), h.DeleteRegionSlangTranslation)
}
func RegisterTraditionRoutes(r *gin.RouterGroup, h *RegionTraditionHandler) {
	r.POST("/tradition/create", middleware.RequireRole("admin"), h.CreateRegionTradition)
	r.GET("/tradition/getById/:id", h.GetRegionTraditionByID)
	r.GET("/:id/traditions", h.GetTraditionsByRegionID)
	r.PATCH("/tradition/update", middleware.RequireRole("admin"), h.UpdateRegionTradition)
	r.DELETE("/tradition/delete/:id", middleware.RequireRole("admin"), h.DeleteRegionTradition)

	// translations
	r.POST("/tradition/translation/create", middleware.RequireRole("admin"), h.CreateRegionTraditionTranslation)
	r.GET("/tradition/translation/getById/:id", h.GetRegionTraditionTranslationByID)
	r.GET("/tradition/:id/translations", h.GetTraditionTranslationsByTraditionID)
	r.PATCH("/tradition/translation/update", middleware.RequireRole("admin"), h.UpdateRegionTraditionTranslation)
	r.DELETE("/tradition/translation/delete/:id", middleware.RequireRole("admin"), h.DeleteRegionTraditionTranslation)
}

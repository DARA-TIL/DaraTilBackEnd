package app

import (
	_ "DaraTilBackendV2/docs"
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/service/folklore"
	"DaraTilBackendV2/internal/presentation/http/service/lesson"
	"DaraTilBackendV2/internal/presentation/http/service/region"
	"DaraTilBackendV2/internal/presentation/http/service/test"
	"DaraTilBackendV2/internal/presentation/http/service/user"
	"DaraTilBackendV2/internal/presentation/http/service/userActivity"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
)

type App struct {
	cfg       *config.Config
	container *Container
	router    *gin.Engine
}

func New(cfg *config.Config) *App {
	return &App{
		cfg:       cfg,
		container: NewContainer(cfg),
		router:    gin.Default(),
	}
}

func (a *App) setupMiddleware() {
	a.router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:8080"},
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		MaxAge:           12 * time.Hour,
	}))
}

func (a *App) setupRoutes() {
	api := a.router.Group("/api")

	//Auth
	auth := api.Group("/auth")
	authSecure := api.Group("/auth")
	authSecure.Use(middleware.AuthMiddleware(a.cfg))

	//user
	userRoute := api.Group("/user")
	userSecure := api.Group("/user")
	userSecure.Use(middleware.AuthMiddleware(a.cfg))
	user.RegisterAuthRoutes(
		auth,
		a.container.UserHandler,
		a.container.JwtHandler,
	)
	user.RegisterAuthProtectedRoutes(authSecure, a.container.JwtHandler)
	user.RegisterRoutes(userRoute, a.container.UserHandler)
	user.RegisterProtectedRoutes(userSecure, a.container.UserHandler)

	//Folklore
	folk := api.Group("/folklore")
	folk.Use(middleware.AuthMiddleware(a.cfg))
	folklore.RegisterRoutes(folk, a.container.FolkloreHandler)

	//Lesson
	lessonRoute := api.Group("/lesson")
	lessonRoute.Use(middleware.AuthMiddleware(a.cfg))
	lesson.RegisterRoutes(lessonRoute, a.container.LessonHandler)

	//Test
	testRoute := api.Group("/test")
	testRoute.Use(middleware.AuthMiddleware(a.cfg))
	test.RegisterProtectedTestRoutes(testRoute, a.container.TestHandler)

	//UserActivities
	activityRoute := api.Group("/activity")
	activityRoute.Use(middleware.AuthMiddleware(a.cfg))
	userActivity.RegisterRoutes(activityRoute, a.container.UserActivityHandler)
	//region
	regionRoute := api.Group("/region")
	regionRoute.Use(middleware.AuthMiddleware(a.cfg))
	region.RegisterRoutes(regionRoute, a.container.RegionHandler)
	region.RegisterSlangRoutes(regionRoute, a.container.RegionSlangHandler)
	region.RegisterTraditionRoutes(regionRoute, a.container.RegionTraditionHandler)
	api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

}

func (a *App) Run() {
	logger.Init(true)
	a.setupMiddleware()
	a.setupRoutes()

	logger.Info("App started:", zap.String("port", a.cfg.Server.Port))
	_ = a.router.Run(":" + a.cfg.Server.Port)
}

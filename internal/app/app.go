package app

import (
	"DaraTilBackendV2/internal/config"
	"DaraTilBackendV2/internal/presentation/http/middleware"
	"DaraTilBackendV2/internal/presentation/http/service/user"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
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
	auth := api.Group("/auth")
	authSecure := api.Group("/auth")
	authSecure.Use(middleware.AuthMiddleware(a.cfg))

	user.RegisterRoutes(
		auth,
		a.container.UserHandler,
		a.container.JwtHandler,
	)
	user.RegisterProtectedRoutes(authSecure, a.container.JwtHandler)
}

func (a *App) Run() {
	a.cfg.SetupSessionStore()
	a.setupMiddleware()
	a.setupRoutes()

	log.Printf("Server started on :%s", a.cfg.Server.Port)
	_ = a.router.Run(":" + a.cfg.Server.Port)
}

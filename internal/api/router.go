package api

import (
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/controller"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/middleware"
)

var router *http.ServeMux

func SetupRoutes(authController controller.AuthController) *http.ServeMux {
	router = http.NewServeMux()
	setupPreflightRoute()
	setupRegisterRoutes(authController)
	setupLoginRoutes(authController)
	setupTokenRoutes(authController)
	return router
}

func applyMiddleware(h middleware.HandlerFunc) http.HandlerFunc {
	return middleware.CorsMiddleware(
		middleware.ErrorHandler(
			middleware.LoggingMiddleware(h),
		),
	)
}

func setupPreflightRoute() {
	router.Handle("OPTIONS /", middleware.CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
}

func setupRegisterRoutes(authController controller.AuthController) {
	router.Handle("POST /register/begin", applyMiddleware(authController.BeginRegister))
	router.Handle("POST /register/finish", applyMiddleware(authController.FinishRegister))
}

func setupLoginRoutes(authController controller.AuthController) {
	router.Handle("POST /login/begin", applyMiddleware(authController.BeginLogin))
	router.Handle("POST /login/finish", applyMiddleware(authController.FinishLogin))
}

func setupTokenRoutes(authController controller.AuthController) {
	router.Handle("POST /refresh", applyMiddleware(authController.Refresh))
}

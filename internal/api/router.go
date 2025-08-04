package api

import (
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/controller"
	"github.com/taekwondodev/go-PassKey-Authentication/internal/middleware"
)

type Router struct {
	mux *http.ServeMux
}

func NewRouter() *Router {
	return &Router{
		mux: http.NewServeMux(),
	}
}

func SetupRoutes(authController controller.AuthController) *http.ServeMux {
	router := NewRouter()
	return router.setupRoutes(authController)
}

func (r *Router) setupRoutes(authController controller.AuthController) *http.ServeMux {
	r.setupPreflightRoute()
	r.setupRegisterRoutes(authController)
	r.setupLoginRoutes(authController)
	r.setupTokenRoutes(authController)
	return r.mux
}

func (r *Router) applyMiddleware(h middleware.HandlerFunc) http.HandlerFunc {
	return middleware.CorsMiddleware(
		middleware.ErrorHandler(
			middleware.LoggingMiddleware(h),
		),
	)
}

func (r *Router) setupPreflightRoute() {
	r.mux.Handle("OPTIONS /", middleware.CorsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
}

func (r *Router) setupRegisterRoutes(authController controller.AuthController) {
	r.mux.Handle("POST /register/begin", r.applyMiddleware(authController.BeginRegister))
	r.mux.Handle("POST /register/finish", r.applyMiddleware(authController.FinishRegister))
}

func (r *Router) setupLoginRoutes(authController controller.AuthController) {
	r.mux.Handle("POST /login/begin", r.applyMiddleware(authController.BeginLogin))
	r.mux.Handle("POST /login/finish", r.applyMiddleware(authController.FinishLogin))
}

func (r *Router) setupTokenRoutes(authController controller.AuthController) {
	r.mux.Handle("POST /refresh", r.applyMiddleware(authController.Refresh))
	r.mux.Handle("POST /logout", r.applyMiddleware(authController.Logout))
}

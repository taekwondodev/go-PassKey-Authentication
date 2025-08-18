package middleware

import (
	"net/http"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/config"
)

func CorsMiddleware(next http.Handler) http.HandlerFunc {
	originConfig, protection := newCSRF()

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", originConfig.FrontendURL)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.Header().Set("Vary", "Origin")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if err := protection.Check(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func newCSRF() (*config.OriginConfig, *http.CrossOriginProtection) {
	protection := http.NewCrossOriginProtection()
	originConfig, _ := config.LoadOriginConfig()
	protection.AddTrustedOrigin(originConfig.FrontendURL)
	return originConfig, protection
}

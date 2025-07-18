package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/taekwondodev/go-PassKey-Authentication/internal/customerrors"
)

func LoggingMiddleware(next HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		start := time.Now()
		fmt.Printf("Started %s %s\n", r.Method, r.URL.Path)

		err := next(w, r)

		duration := time.Since(start)
		status := http.StatusOK
		if err != nil {
			status = customerrors.GetStatus(err)
		}

		fmt.Printf("Completed %s %s | Status: %d | Duration: %v\n",
			r.Method, r.URL.Path, status, duration)

		return err
	}
}

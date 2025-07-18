package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server struct {
	*http.Server
	shutdownTimeout time.Duration
}

func NewServer(addr string, router *http.ServeMux) *Server {
	return &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: router,
		},
		shutdownTimeout: 10 * time.Second,
	}
}

func (s *Server) StartWithGracefulShutdown() {
	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- s.start()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or an error
	select {
	case err := <-serverErrors:
		panic(fmt.Errorf("Error starting server: %v", err))

	case <-shutdown:
		fmt.Println("Starting graceful shutdown...")

		ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()

		if err := s.shutdown(ctx); err != nil {
			fmt.Println("Could not gracefully shutdown the server:", err)

			if err := s.Close(); err != nil {
				fmt.Println("Could not close server:", err)
			}
		}
		fmt.Println("Server gracefully stopped")
	}
}

func (s *Server) start() error {
	fmt.Println("Server listening on", s.Addr)
	return s.ListenAndServe()
}

func (s *Server) shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}

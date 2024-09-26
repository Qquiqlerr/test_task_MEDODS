package main

import (
	"github.com/go-chi/chi/v5"
	"log/slog"
	"net/http"
	"os"
	"testMedods/internal/config"
	"testMedods/internal/http-server/handlers/auth"
	"testMedods/internal/storage"
)

func main() {
	r := chi.NewRouter()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	cfg := config.MustLoad()
	db, err := storage.New()
	if err != nil {
		panic("Can't connect to database")
	}
	r.Post("/auth/token", auth.GetJWTPair(log, db, cfg))
	r.Post("/auth/refresh", auth.RefreshToken(log, db, cfg))
	log.Info("starting server", slog.String("address", cfg.Address))
	srv := http.Server{
		Addr:    cfg.Address,
		Handler: r,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("failed to start server", err.Error())
	}

	log.Error("server stopped")
}

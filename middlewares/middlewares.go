package middlewares

import (
	"github.com/gorilla/mux"
)

var (
	Funcs = []mux.MiddlewareFunc{hstsMiddleware}
)

func init() {
}

func AddMiddlewares(r *mux.Router) {
	for _, v := range Funcs {
		r.Use(v)
	}
}

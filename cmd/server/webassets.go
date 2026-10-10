package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets
var embeddedAssets embed.FS

// staticHandler 返回内嵌的本地前端资源（Bootstrap 等全部随二进制分发，运行时无外部 CDN）。
func staticHandler() http.Handler {
	sub, err := fs.Sub(embeddedAssets, "assets")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			// SPA 兜底
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

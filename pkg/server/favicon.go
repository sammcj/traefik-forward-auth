package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	issvg "github.com/h2non/go-is-svg"

	"github.com/italypaleale/traefik-forward-auth/pkg/config"
)

func (s *Server) loadFavicon() error {
	cfg := config.Get()
	if cfg.Server.Favicon == "" {
		s.favicon = nil
		return nil
	}

	// Create the request
	req, err := http.NewRequest(http.MethodGet, cfg.Server.Favicon, nil)
	if err != nil {
		return fmt.Errorf("failed to create the favicon request for URL '%s': %w", cfg.Server.Favicon, err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download favicon from '%s': %w", cfg.Server.Favicon, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("failed to download favicon from '%s': received HTTP status %d", cfg.Server.Favicon, resp.StatusCode)
	}

	// Read the response, max 2MB
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("failed to read downloaded favicon data: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("downloaded favicon from '%s' is empty", cfg.Server.Favicon)
	}

	// Detect favicon type
	favicon, err := detectFavicon(data)
	if err != nil {
		return err
	}
	s.favicon = favicon

	return nil
}

func detectFavicon(data []byte) (*appFavicon, error) {
	// PNG magic bytes
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return &appFavicon{
			Path:        "favicon.png",
			ContentType: "image/png",
			LinkType:    "image/png",
			Data:        data,
		}, nil
	}

	// ICO magic bytes
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00 {
		return &appFavicon{
			Path:        "favicon.ico",
			ContentType: "image/x-icon",
			Data:        data,
		}, nil
	}

	// Check if it's a SVG
	if issvg.IsSVG(data) {
		return &appFavicon{
			Path:        "favicon.svg",
			ContentType: "image/svg+xml",
			LinkType:    "image/svg+xml",
			LinkSizes:   "any",
			Data:        data,
		}, nil
	}

	return nil, errors.New("unsupported favicon file format: only PNG, ICO, and SVG are allowed")
}

func (s *Server) addFaviconRoute(basePath string) {
	if s.favicon == nil {
		return
	}

	s.appRouter.GET(
		path.Join(basePath, s.favicon.Path),
		s.addClientCacheHeaders(30*86400),
		func(c *gin.Context) {
			c.Header("Content-Type", s.favicon.ContentType)
			_, _ = c.Writer.Write(s.favicon.Data)
		},
	)
}

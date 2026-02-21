package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectFavicon(t *testing.T) {
	t.Run("png", func(t *testing.T) {
		data := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.png", f.Path)
		assert.Equal(t, "image/png", f.ContentType)
		assert.Equal(t, "image/png", f.LinkType)
		assert.Empty(t, f.LinkSizes)
	})

	t.Run("ico", func(t *testing.T) {
		data := []byte{0x00, 0x00, 0x01, 0x00, 0x10}
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.ico", f.Path)
		assert.Equal(t, "image/x-icon", f.ContentType)
		assert.Empty(t, f.LinkType)
		assert.Empty(t, f.LinkSizes)
	})

	t.Run("svg", func(t *testing.T) {
		data := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`)
		f, err := detectFavicon(data)
		require.NoError(t, err)
		assert.Equal(t, "favicon.svg", f.Path)
		assert.Equal(t, "image/svg+xml", f.ContentType)
		assert.Equal(t, "image/svg+xml", f.LinkType)
		assert.Equal(t, "any", f.LinkSizes)
	})

	t.Run("unsupported", func(t *testing.T) {
		_, err := detectFavicon([]byte("GIF89a"))
		require.Error(t, err)
		assert.ErrorContains(t, err, "unsupported favicon file format")
	})
}

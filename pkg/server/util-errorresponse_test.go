package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetResponseError(t *testing.T) {
	t.Run("defaults to internal server error for generic error", func(t *testing.T) {
		errRes := getResponseError(errors.New("boom"))
		assert.Equal(t, http.StatusInternalServerError, errRes.Code)
		assert.Equal(t, internalServerErrorMessage, errRes.Message)
	})

	t.Run("preserves non-5xx response errors", func(t *testing.T) {
		errRes := getResponseError(NewResponseError(http.StatusBadRequest, "bad request"))
		assert.Equal(t, http.StatusBadRequest, errRes.Code)
		assert.Equal(t, "bad request", errRes.Message)
	})

	t.Run("masks 5xx response errors", func(t *testing.T) {
		errRes := getResponseError(NewResponseError(http.StatusInternalServerError, "private details"))
		assert.Equal(t, http.StatusInternalServerError, errRes.Code)
		assert.Equal(t, internalServerErrorMessage, errRes.Message)
	})

	t.Run("invalid token errors are masked and always unauthorized", func(t *testing.T) {
		errRes := getResponseError(NewInvalidTokenError("jwt signature invalid"))
		assert.Equal(t, http.StatusUnauthorized, errRes.Code)
		assert.Equal(t, "Access token is invalid", errRes.Message)
	})

	t.Run("wrapped invalid token errors are also masked", func(t *testing.T) {
		err := errors.Join(errors.New("outer"), NewInvalidTokenError("private token message"))
		errRes := getResponseError(err)
		assert.Equal(t, http.StatusUnauthorized, errRes.Code)
		assert.Equal(t, "Access token is invalid", errRes.Message)
	})
}

func TestAbortWithErrorAndAbortWithErrorJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("AbortWithError writes plain text error and aborts context", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)

		AbortWithError(c, NewResponseError(http.StatusBadRequest, "bad input"))

		assert.True(t, c.IsAborted())
		require.Len(t, c.Errors, 1)
		assert.Equal(t, "bad input", c.Errors[0].Error())
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, "Error: bad input", rec.Body.String())
		assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	})

	t.Run("AbortWithError masks internal server errors", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)

		AbortWithError(c, NewResponseError(http.StatusInternalServerError, "private details"))

		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, "Error: "+internalServerErrorMessage, rec.Body.String())
	})

	t.Run("AbortWithErrorJSON writes JSON payload and masks invalid token message", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)

		AbortWithErrorJSON(c, NewInvalidTokenError("sensitive token parse failure"))

		assert.True(t, c.IsAborted())
		require.Len(t, c.Errors, 1)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var got map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, "Access token is invalid", got["error"])
	})
}

func TestInvalidTokenErrorJSONMasking(t *testing.T) {
	err := NewInvalidTokenError("private details")
	payload, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)
	assert.JSONEq(t, `{"error":"Access token is invalid"}`, string(payload))
}

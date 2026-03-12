package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogoutService(t *testing.T) {
	service := NewLogoutService(nil, 0, 0)
	assert.NotNil(t, service)
}

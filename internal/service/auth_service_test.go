package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	password := "Test123!"

	hash, err := hashPassword(password)

	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$")

	hash2, err := hashPassword(password)
	require.NoError(t, err)
	assert.NotEqual(t, hash, hash2)
}

func TestCheckPassword_Success(t *testing.T) {
	password := "Test123!"
	hash, err := hashPassword(password)
	require.NoError(t, err)

	valid := checkPassword(hash, password)

	assert.True(t, valid)
}

func TestCheckPassword_Failure(t *testing.T) {
	password := "Test123!"
	wrongPassword := "Wrong456!"
	hash, err := hashPassword(password)
	require.NoError(t, err)

	valid := checkPassword(hash, wrongPassword)

	assert.False(t, valid)
}

func TestCheckPassword_InvalidHash(t *testing.T) {
	invalidHash := "invalid_hash_format"
	password := "Test123!"

	valid := checkPassword(invalidHash, password)

	assert.False(t, valid)
}

func TestCheckPassword_EmptyPassword(t *testing.T) {
	password := "Test123!"
	hash, err := hashPassword(password)
	require.NoError(t, err)

	valid := checkPassword(hash, "")

	assert.False(t, valid)
}

func TestCheckPassword_EmptyHash(t *testing.T) {
	password := "Test123!"

	valid := checkPassword("", password)

	assert.False(t, valid)
}

func TestCheckPassword_NoSeparator(t *testing.T) {
	invalidHash := "noseparator"
	password := "Test123!"

	valid := checkPassword(invalidHash, password)

	assert.False(t, valid)
}

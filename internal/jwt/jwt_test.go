package jwt

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTManager_Generate(t *testing.T) {
	secretKey := "test-secret-key"
	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 168 * time.Hour
	manager := NewJWTManager(secretKey, accessTokenTTL, refreshTokenTTL)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)

	require.NoError(t, err)
	require.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.NotEqual(t, tokens.AccessToken, tokens.RefreshToken)
}

func TestJWTManager_Validate(t *testing.T) {
	secretKey := "test-secret-key"
	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 168 * time.Hour
	manager := NewJWTManager(secretKey, accessTokenTTL, refreshTokenTTL)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	claims, err := manager.Validate(tokens.AccessToken)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, phone, claims.Phone)
}

func TestJWTManager_Validate_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	invalidToken := "invalid.token.here"

	claims, err := manager.Validate(invalidToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Validate_WrongSecret(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)
	wrongManager := NewJWTManager("wrong-secret", 15*time.Minute, 168*time.Hour)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	claims, err := wrongManager.Validate(tokens.AccessToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_ValidateRefresh(t *testing.T) {
	secretKey := "test-secret-key"
	manager := NewJWTManager(secretKey, 15*time.Minute, 168*time.Hour)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	validatedUserID, err := manager.ValidateRefresh(tokens.RefreshToken)

	require.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)
}

func TestJWTManager_ValidateRefreshWithJTI(t *testing.T) {
	secretKey := "test-secret-key"
	manager := NewJWTManager(secretKey, 15*time.Minute, 168*time.Hour)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	claims, err := manager.ValidateRefreshWithJTI(tokens.RefreshToken)

	require.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, userID.String(), claims.Subject)
	assert.NotEmpty(t, claims.ID)
}

func TestJWTManager_ValidateRefresh_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	invalidToken := "invalid.refresh.token"

	userID, err := manager.ValidateRefresh(invalidToken)

	assert.Error(t, err)
	assert.Equal(t, uuid.Nil, userID)
}

func TestJWTManager_ValidateRefreshWithJTI_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	invalidToken := "invalid.refresh.token"

	claims, err := manager.ValidateRefreshWithJTI(invalidToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Validate_ExpiredToken(t *testing.T) {
	secretKey := "test-secret-key"
	manager := NewJWTManager(secretKey, -1*time.Hour, 168*time.Hour)

	userID := uuid.New()
	phone := "+79991234567"

	tokens, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	claims, err := manager.Validate(tokens.AccessToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Generate_DifferentTokens(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	userID := uuid.New()
	phone := "+79991234567"

	tokens1, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	tokens2, err := manager.Generate(userID, phone)
	require.NoError(t, err)

	assert.NotEqual(t, tokens1.AccessToken, tokens2.AccessToken)
	assert.NotEqual(t, tokens1.RefreshToken, tokens2.RefreshToken)
}

func TestJWTManager_Validate_EmptyToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	claims, err := manager.Validate("")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_ValidateRefresh_EmptyToken(t *testing.T) {
	manager := NewJWTManager("test-secret", 15*time.Minute, 168*time.Hour)

	userID, err := manager.ValidateRefresh("")

	assert.Error(t, err)
	assert.Equal(t, uuid.Nil, userID)
}

func TestNewJWTManager(t *testing.T) {
	secretKey := "my-secret-key"
	accessTokenTTL := 30 * time.Minute
	refreshTokenTTL := 24 * time.Hour

	manager := NewJWTManager(secretKey, accessTokenTTL, refreshTokenTTL)

	require.NotNil(t, manager)
	assert.Equal(t, secretKey, manager.secretKey)
	assert.Equal(t, accessTokenTTL, manager.accessTokenTTL)
	assert.Equal(t, refreshTokenTTL, manager.refreshTokenTTL)
}

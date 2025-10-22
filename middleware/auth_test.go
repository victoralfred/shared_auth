package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/victoralfred/shared_auth/crypto"
	"github.com/victoralfred/shared_auth/jwt"
)

func setupTestRouter(verifier jwt.Verifier) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	return router
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate valid token
	claims := jwt.CreateTestClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	// Setup router with middleware
	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/test", func(c *gin.Context) {
		userID, _ := GetUserID(c)
		c.JSON(200, gin.H{"user_id": userID})
	})

	// Make request with valid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), claims.UserID)
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Make request without token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Make request with invalid token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token")
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	// Generate expired token
	claims := jwt.CreateExpiredClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	// Make request with expired token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
}

func TestRequirePermission_HasPermission(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	claims := jwt.CreateTestClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/orders",
		RequirePermission("orders", "create"),
		func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		},
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestRequirePermission_MissingPermission(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	claims := jwt.CreateTestClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.DELETE("/orders",
		RequirePermission("orders", "delete"), // User doesn't have delete permission
		func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		},
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/orders", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Contains(t, w.Body.String(), "Forbidden")
}

func TestRequireRole_HasRole(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	claims := jwt.CreateTestClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/manager",
		RequireRole("manager"), // User has manager role
		func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		},
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/manager", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

func TestRequireRole_MissingRole(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	claims := jwt.CreateTestClaims()
	token, err := jwt.GenerateTestToken(privateKey, claims)
	require.NoError(t, err)

	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))
	router.GET("/admin",
		RequireRole("admin"), // User doesn't have admin role
		func(c *gin.Context) {
			c.JSON(200, gin.H{"ok": true})
		},
	)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
}

func TestRequireAdmin(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	tests := []struct {
		name         string
		roles        []string
		expectedCode int
	}{
		{
			name:         "admin role - allowed",
			roles:        []string{"admin"},
			expectedCode: 200,
		},
		{
			name:         "super_admin role - allowed",
			roles:        []string{"super_admin"},
			expectedCode: 200,
		},
		{
			name:         "regular user - denied",
			roles:        []string{"user", "manager"},
			expectedCode: 403,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.CreateTestClaims()
			claims.Roles = tt.roles
			token, err := jwt.GenerateTestToken(privateKey, claims)
			require.NoError(t, err)

			router := setupTestRouter(verifier)
			router.Use(AuthMiddleware(verifier))
			router.GET("/admin",
				RequireAdmin(),
				func(c *gin.Context) {
					c.JSON(200, gin.H{"ok": true})
				},
			)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/admin", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)
		})
	}
}

func TestOptionalAuthMiddleware(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "test-service")

	router := setupTestRouter(verifier)
	router.Use(OptionalAuthMiddleware(verifier))
	router.GET("/public", func(c *gin.Context) {
		userID, exists := GetUserID(c)
		if exists {
			c.JSON(200, gin.H{"authenticated": true, "user_id": userID})
		} else {
			c.JSON(200, gin.H{"authenticated": false})
		}
	})

	// Test with token
	t.Run("with valid token", func(t *testing.T) {
		claims := jwt.CreateTestClaims()
		token, err := jwt.GenerateTestToken(privateKey, claims)
		require.NoError(t, err)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/public", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), `"authenticated":true`)
	})

	// Test without token
	t.Run("without token", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/public", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), `"authenticated":false`)
	})
}

func TestRealWorldEcommerce(t *testing.T) {
	privateKey, err := crypto.LoadPrivateKeyFromFile("../testdata/jwt-private.pem")
	require.NoError(t, err)

	publicKey, err := crypto.LoadPublicKeyFromFile("../testdata/jwt-public.pem")
	require.NoError(t, err)

	verifier := jwt.NewVerifier(publicKey, "kubemanager", "order-service")

	// Create customer token
	customerClaims := &jwt.Claims{
		Subject:   "cust-123",
		Issuer:    "kubemanager",
		Audience:  "order-service",
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		NotBefore: time.Now().Unix(),
		IssuedAt:  time.Now().Unix(),
		UserID:    "cust-123",
		TenantID:  "acme-corp",
		Email:     "john@acme.com",
		Roles:     []string{"customer"},
		Permissions: map[string][]string{
			"orders":   {"create", "read", "cancel"},
			"products": {"read", "review"},
			"cart":     {"*"},
		},
		TokenType: "access",
	}
	customerToken, err := jwt.GenerateTestToken(privateKey, customerClaims)
	require.NoError(t, err)

	// Setup router
	router := setupTestRouter(verifier)
	router.Use(AuthMiddleware(verifier))

	// Order endpoints
	router.POST("/orders", RequirePermission("orders", "create"), func(c *gin.Context) {
		claims, _ := GetClaims(c)
		c.JSON(200, gin.H{"message": "Order created", "user_id": claims.UserID})
	})

	router.GET("/orders", RequirePermission("orders", "read"), func(c *gin.Context) {
		c.JSON(200, gin.H{"orders": []string{"order-1", "order-2"}})
	})

	router.DELETE("/orders/1", RequirePermission("orders", "delete"), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Order deleted"})
	})

	// Test customer can create order
	t.Run("customer creates order", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/orders", nil)
		req.Header.Set("Authorization", "Bearer "+customerToken)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Contains(t, w.Body.String(), "cust-123")
	})

	// Test customer can read orders
	t.Run("customer reads orders", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/orders", nil)
		req.Header.Set("Authorization", "Bearer "+customerToken)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	// Test customer cannot delete order
	t.Run("customer cannot delete order", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/orders/1", nil)
		req.Header.Set("Authorization", "Bearer "+customerToken)
		router.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
	})
}

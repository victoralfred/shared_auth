package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/victoralfred/shared_auth/cache"
	"github.com/victoralfred/shared_auth/crypto"
	"github.com/victoralfred/shared_auth/events"
	"github.com/victoralfred/shared_auth/jwt"
	"github.com/victoralfred/shared_auth/middleware"
	"github.com/victoralfred/shared_auth/policy"
)

type OrderService struct {
	jwtVerifier   *jwt.Verifier
	policyEngine  *policy.Engine
	eventConsumer *events.RabbitMQConsumer
}

func main() {
	// Load public key
	publicKey, err := crypto.LoadPublicKeyFromFile(getEnv("JWT_PUBLIC_KEY", "../../testdata/jwt-public.pem"))
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	// Create JWT verifier
	verifier := jwt.NewVerifier(
		publicKey,
		getEnv("JWT_ISSUER", "kubemanager"),
		getEnv("JWT_AUDIENCE", "order-service"),
	)

	// Create policy engine with cache
	memCache := cache.NewMemoryCache(10000)
	policyEngine := policy.NewEngine(memCache)

	// Load initial policies (in production, fetch from API)
	initialPolicies := loadInitialPolicies()
	if err := policyEngine.LoadPolicies(initialPolicies); err != nil {
		log.Fatalf("Failed to load policies: %v", err)
	}

	// Setup RabbitMQ consumer for policy updates
	rabbitmqURL := getEnv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
	rabbitmqExchange := getEnv("RABBITMQ_EXCHANGE", "kubemanager.events")
	rabbitmqQueue := getEnv("RABBITMQ_QUEUE", "order-service-security")
	routingKeys := []string{"policy.update", "user.event"}

	consumer, err := events.NewRabbitMQConsumer(rabbitmqURL, rabbitmqExchange, rabbitmqQueue, routingKeys)
	if err != nil {
		log.Fatalf("Failed to create RabbitMQ consumer: %v", err)
	}

	// Start consuming policy updates in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := consumer.ConsumePolicyUpdates(ctx, func(event events.PolicyUpdateEvent) {
			log.Printf("Received policy update: %s for tenant %s", event.Event, event.TenantID)
			// Update local policy engine
			// In production, convert event.Policies to []policy.Policy
		}); err != nil {
			log.Printf("Policy consumer error: %v", err)
		}
	}()

	// Create service
	service := &OrderService{
		jwtVerifier:  verifier,
		policyEngine: policyEngine,
		eventConsumer: consumer,
	}

	// Setup Gin router
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		stats := policyEngine.Stats()
		c.JSON(200, gin.H{
			"status": "healthy",
			"policy_stats": gin.H{
				"policies":      stats.PolicyCount,
				"cached_items":  stats.CachedItems,
				"cache_hit_rate": stats.CacheHitRate,
			},
		})
	})

	// Apply authentication middleware
	api := router.Group("/api")
	api.Use(middleware.AuthMiddleware(verifier))
	api.Use(middleware.TenantMiddleware())
	{
		// Order endpoints
		api.POST("/orders",
			middleware.RequirePermission("orders", "create"),
			service.createOrder,
		)

		api.GET("/orders",
			middleware.RequirePermission("orders", "read"),
			service.listOrders,
		)

		api.GET("/orders/:id",
			middleware.RequirePermission("orders", "read"),
			service.getOrder,
		)

		api.PUT("/orders/:id",
			middleware.RequirePermission("orders", "update"),
			service.updateOrder,
		)

		api.DELETE("/orders/:id",
			middleware.RequirePermission("orders", "delete"),
			service.deleteOrder,
		)
	}

	// Start server
	go func() {
		log.Println("Starting order service on :8080")
		if err := router.Run(":8080"); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down order service...")
	consumer.Close()
}

func (s *OrderService) createOrder(c *gin.Context) {
	claims, _ := middleware.GetClaims(c)

	// Create order using data from token (no database lookup for user)
	order := map[string]interface{}{
		"id":         generateID(),
		"user_id":    claims.UserID,
		"tenant_id":  claims.TenantID,
		"created_by": claims.Email,
		"created_at": time.Now(),
		"status":     "pending",
	}

	c.JSON(200, gin.H{
		"message": "Order created successfully",
		"order":   order,
	})
}

func (s *OrderService) listOrders(c *gin.Context) {
	tenantID, _ := middleware.GetTenantID(c)

	c.JSON(200, gin.H{
		"orders": []map[string]interface{}{
			{"id": "1", "tenant_id": tenantID, "status": "pending"},
			{"id": "2", "tenant_id": tenantID, "status": "completed"},
		},
	})
}

func (s *OrderService) getOrder(c *gin.Context) {
	orderID := c.Param("id")
	tenantID, _ := middleware.GetTenantID(c)

	c.JSON(200, gin.H{
		"order": map[string]interface{}{
			"id":        orderID,
			"tenant_id": tenantID,
			"status":    "pending",
		},
	})
}

func (s *OrderService) updateOrder(c *gin.Context) {
	orderID := c.Param("id")

	c.JSON(200, gin.H{
		"message": "Order updated successfully",
		"order_id": orderID,
	})
}

func (s *OrderService) deleteOrder(c *gin.Context) {
	orderID := c.Param("id")

	c.JSON(200, gin.H{
		"message": "Order deleted successfully",
		"order_id": orderID,
	})
}

func loadInitialPolicies() []policy.Policy {
	return []policy.Policy{
		{
			ID:       "order-full-access",
			TenantID: "default",
			Resource: "orders",
			Actions:  []string{"*"},
			Roles:    []string{"admin", "manager"},
			Priority: 100,
		},
		{
			ID:       "order-read-only",
			TenantID: "default",
			Resource: "orders",
			Actions:  []string{"read"},
			Roles:    []string{"customer"},
			Priority: 50,
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateID() string {
	return time.Now().Format("20060102150405")
}

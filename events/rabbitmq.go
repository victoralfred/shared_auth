package events

import (
	"context"
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// RabbitMQPublisher publishes events to RabbitMQ
type RabbitMQPublisher struct {
	conn     *amqp.Connection
	channel  *amqp.Channel
	exchange string
}

// NewRabbitMQPublisher creates a new RabbitMQ publisher
func NewRabbitMQPublisher(url, exchange string) (*RabbitMQPublisher, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Declare exchange (fanout for broadcasting)
	err = channel.ExchangeDeclare(
		exchange, // name
		"topic",  // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		channel.Close()
		conn.Close()
		return nil, err
	}

	return &RabbitMQPublisher{
		conn:     conn,
		channel:  channel,
		exchange: exchange,
	}, nil
}

// PublishPolicyUpdate publishes policy update event
func (p *RabbitMQPublisher) PublishPolicyUpdate(ctx context.Context, event PolicyUpdateEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return p.channel.PublishWithContext(
		ctx,
		p.exchange,           // exchange
		"policy.update",      // routing key
		false,                // mandatory
		false,                // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         data,
			Timestamp:    time.Now(),
			DeliveryMode: amqp.Persistent,
		},
	)
}

// PublishUserEvent publishes user-related event
func (p *RabbitMQPublisher) PublishUserEvent(ctx context.Context, event UserEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return p.channel.PublishWithContext(
		ctx,
		p.exchange,      // exchange
		"user.event",    // routing key
		false,           // mandatory
		false,           // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         data,
			Timestamp:    time.Now(),
			DeliveryMode: amqp.Persistent,
		},
	)
}

// PublishCacheInvalidate publishes cache invalidation event
func (p *RabbitMQPublisher) PublishCacheInvalidate(ctx context.Context, event CacheInvalidateEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return p.channel.PublishWithContext(
		ctx,
		p.exchange,           // exchange
		"cache.invalidate",   // routing key
		false,                // mandatory
		false,                // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			Body:         data,
			Timestamp:    time.Now(),
			DeliveryMode: amqp.Persistent,
		},
	)
}

// Close closes the publisher
func (p *RabbitMQPublisher) Close() error {
	if err := p.channel.Close(); err != nil {
		return err
	}
	return p.conn.Close()
}

// RabbitMQConsumer consumes events from RabbitMQ
type RabbitMQConsumer struct {
	conn      *amqp.Connection
	channel   *amqp.Channel
	queue     string
	exchange  string
}

// NewRabbitMQConsumer creates a new RabbitMQ consumer
func NewRabbitMQConsumer(url, exchange, queueName string, routingKeys []string) (*RabbitMQConsumer, error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Declare exchange
	err = channel.ExchangeDeclare(
		exchange, // name
		"topic",  // type
		true,     // durable
		false,    // auto-deleted
		false,    // internal
		false,    // no-wait
		nil,      // arguments
	)
	if err != nil {
		channel.Close()
		conn.Close()
		return nil, err
	}

	// Declare queue
	queue, err := channel.QueueDeclare(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		channel.Close()
		conn.Close()
		return nil, err
	}

	// Bind queue to exchange with routing keys
	for _, routingKey := range routingKeys {
		err = channel.QueueBind(
			queue.Name, // queue name
			routingKey, // routing key
			exchange,   // exchange
			false,
			nil,
		)
		if err != nil {
			channel.Close()
			conn.Close()
			return nil, err
		}
	}

	return &RabbitMQConsumer{
		conn:     conn,
		channel:  channel,
		queue:    queue.Name,
		exchange: exchange,
	}, nil
}

// ConsumePolicyUpdates consumes policy update events
func (c *RabbitMQConsumer) ConsumePolicyUpdates(ctx context.Context, handler func(PolicyUpdateEvent)) error {
	msgs, err := c.channel.Consume(
		c.queue, // queue
		"",      // consumer
		false,   // auto-ack
		false,   // exclusive
		false,   // no-local
		false,   // no-wait
		nil,     // args
	)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-msgs:
			if !ok {
				return nil
			}

			var event PolicyUpdateEvent
			if err := json.Unmarshal(msg.Body, &event); err != nil {
				log.Printf("Error unmarshaling event: %v", err)
				msg.Nack(false, false)
				continue
			}

			// Handle event
			handler(event)

			// Acknowledge message
			if err := msg.Ack(false); err != nil {
				log.Printf("Error acknowledging message: %v", err)
			}
		}
	}
}

// ConsumeUserEvents consumes user-related events
func (c *RabbitMQConsumer) ConsumeUserEvents(ctx context.Context, handler func(UserEvent)) error {
	msgs, err := c.channel.Consume(
		c.queue, // queue
		"",      // consumer
		false,   // auto-ack
		false,   // exclusive
		false,   // no-local
		false,   // no-wait
		nil,     // args
	)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-msgs:
			if !ok {
				return nil
			}

			var event UserEvent
			if err := json.Unmarshal(msg.Body, &event); err != nil {
				log.Printf("Error unmarshaling event: %v", err)
				msg.Nack(false, false)
				continue
			}

			// Handle event
			handler(event)

			// Acknowledge message
			if err := msg.Ack(false); err != nil {
				log.Printf("Error acknowledging message: %v", err)
			}
		}
	}
}

// Close closes the consumer
func (c *RabbitMQConsumer) Close() error {
	if err := c.channel.Close(); err != nil {
		return err
	}
	return c.conn.Close()
}

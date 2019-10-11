package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/gofrs/uuid"
	"github.com/streadway/amqp"
	"github.com/fredericalix/yic_auth"
)

const (
	// NotifyAdd for the token update action
	NotifyAdd = "add"
	// NotifyRevoke for the token update action
	NotifyRevoke = "revoke"
)

// newTokenNotificationService to notify and serve RPC request for endpoint service to validate
// authentification and authorization
func newTokenNotificationService(conn *amqp.Connection, store *PostgreSQL) (*rabbitMQService, error) {
	var err error
	s := &rabbitMQService{}
	s.ch, err = conn.Channel()
	if err != nil {
		return nil, err
	}
	err = s.ch.ExchangeDeclare(
		"token_update", // name
		"fanout",       // type
		true,           // durable
		false,          // auto-deleted
		false,          // internal
		false,          // no-wait
		nil,            // arguments
	)
	if err != nil {
		return nil, err
	}
	err = s.ch.ExchangeDeclare(
		"account", // name
		"fanout",  // type
		true,      // durable
		false,     // auto-deleted
		false,     // internal
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return nil, err
	}

	// RPC
	rpcch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	q, err := rpcch.QueueDeclare(
		"rpc_session_auth", // name
		false,              // durable
		false,              // delete when usused
		false,              // exclusive
		false,              // no-wait
		nil,                // arguments
	)
	if err != nil {
		return nil, err
	}
	err = rpcch.Qos(
		1,     // prefetch count
		0,     // prefetch size
		false, // global
	)
	if err != nil {
		return nil, err
	}
	msgs, err := rpcch.Consume(
		q.Name, // queue
		"auth", // consumer
		false,  // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return nil, err
	}

	go func() {
		for msg := range msgs {
			var res struct {
				Roles auth.Roles `json:"roles"`
			}
			err := json.Unmarshal(msg.Body, &res)
			if err != nil {
				log.Println("RPC session auth:", err)
				continue
			}

			var responce json.RawMessage
			at, err := store.AllAppToken()
			if err == nil && at != nil {

				// remove not wanted roles
				for i := 0; i < len(at); i++ {
					if match, _ := at[i].Roles.IsMatching(res.Roles); !match {
						at[i] = at[len(at)-1]
						at = at[:len(at)-1]
						i--
					}
				}

				responce, err = json.Marshal(at)
				if err != nil {
					log.Println("RPC session auth:", err)
					continue
				}
			}
			log.Println("RPC session auth", len(at), "tokens for", res.Roles)

			err = rpcch.Publish(
				"",          // exchange
				msg.ReplyTo, // routing key
				false,       // mandatory
				false,       // immediate
				amqp.Publishing{
					ContentType:   "text/plain",
					CorrelationId: msg.CorrelationId,
					Body:          []byte(responce),
				})
			if err != nil {
				log.Println("RPC session auth publish response:", err)
			}

			msg.Ack(false)
		}
	}()

	return s, nil
}

type rabbitMQService struct {
	ch *amqp.Channel
}

// notify the change of a token with 'add' or 'revoke' action
func (s *rabbitMQService) notify(at *auth.AppToken, action string) error {
	content, err := json.Marshal(map[string]interface{}{
		"app_token": at,
		"action":    action,
	})
	if err != nil {
		return err
	}
	err = s.ch.Publish(
		"token_update", // exchange
		"",             // routing key
		false,          // mandatory
		false,          // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "text/json",
			Body:         content,
			AppId:        "auth_service",
		})
	// fmt.Println("**** RabbitMQ ****", at.Token, action)
	return err
}

func (s *rabbitMQService) notifyAccountDeleted(aid uuid.UUID) error {
	err := s.ch.Publish(
		"account",                     // exchange
		fmt.Sprintf("%s.delete", aid), // routing key
		false,                         // mandatory
		false,                         // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			AppId:        "auth_service",
		})
	// fmt.Println("**** RabbitMQ **** delete account", aid)
	return err
}

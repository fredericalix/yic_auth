package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"

	"github.com/streadway/amqp"
)

// NewValidAMQPCache accept or refuse the request base on the validity of the token and the associated roles attached to it.
//
// It listen for new token to be emit on an amqp channel and keep a local cache.
// At startup it retrive every token that satisfy the wanted roles.
func NewValidAMQPCache(conn *amqp.Connection, wanted Roles, fallback ValidSession) (ValidSession, error) {
	sessions := new(sync.Map)
	err := retrivedTokens(conn, wanted, sessions)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	go listenTokenUpdate(ch, wanted, sessions)

	return &validAMQPCache{
		sessions: sessions,
		fallback: fallback,
	}, nil
}

type validAMQPCache struct {
	sessions *sync.Map
	fallback ValidSession
}

func (v validAMQPCache) Valid(ctx context.Context, token string) (Account, Roles, error) {
	cache, found := v.sessions.Load(token)
	if !found {
		if v.fallback == nil {
			return Account{}, Roles{}, fmt.Errorf("token invalid")
		}
		return v.fallback.Valid(ctx, token)
	}
	at := cache.(AppToken)

	return *at.Account, at.Roles, nil
}

func retrivedTokens(conn *amqp.Connection, wanted Roles, cache *sync.Map) error {
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer ch.Close()

	q, err := ch.QueueDeclare(
		"",    // name
		false, // durable
		true,  // delete when usused
		true,  // exclusive
		false, // noWait
		nil,   // arguments
	)
	if err != nil {
		return err
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		return err
	}

	corrID := randomString(32)

	body, err := json.Marshal(map[string]interface{}{"roles": wanted})

	err = ch.Publish(
		"",                 // exchange
		"rpc_session_auth", // routing key
		false,              // mandatory
		false,              // immediate
		amqp.Publishing{
			ContentType:   "text/plain",
			CorrelationId: corrID,
			ReplyTo:       q.Name,
			Body:          body,
		})
	if err != nil {
		return nil
	}

	for d := range msgs {
		if corrID == d.CorrelationId {
			if len(d.Body) == 0 {
				log.Println("RPC session auth got", 0, "sessions for", wanted)
				break
			}
			var res []AppToken
			err = json.Unmarshal(d.Body, &res)
			if err != nil {
				return fmt.Errorf("%v: %s", err, d.Body)
			}
			// populate the session cache
			for _, at := range res {
				cache.Store(at.Token, at)
			}
			log.Println("RPC session auth got", len(res), "sessions for", wanted)

			break
		}
	}

	return nil
}

func listenTokenUpdate(ch *amqp.Channel, wanted Roles, cache *sync.Map) {
	err := ch.ExchangeDeclarePassive(
		"token_update", // name
		"fanout",       // type
		true,           // durable
		false,          // auto-deleted
		false,          // internal
		false,          // no-wait
		nil,            // arguments
	)
	if err != nil {
		log.Panicln(err)
	}

	q, err := ch.QueueDeclare(
		"",    // name
		false, // durable
		false, // delete when usused
		true,  // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		log.Panicln(err)
	}

	err = ch.QueueBind(
		q.Name,         // queue name
		"",             // routing key
		"token_update", // exchange
		false,          // no-wait
		nil)
	if err != nil {
		log.Panicln(err)
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		log.Panicln(err)
	}

	for msg := range msgs {
		var res struct {
			AppToken AppToken `json:"app_token"`
			Action   string   `json:"action"`
		}
		json.Unmarshal(msg.Body, &res)

		switch res.Action {
		case "add":
			if match, _ := res.AppToken.Roles.IsMatching(wanted); match {
				cache.Store(res.AppToken.Token, res.AppToken)
				log.Println("Add")
			}
		case "revoke":
			cache.Delete(res.AppToken.Token)
		}
	}
}

func randomString(l int) string {
	bytes := make([]byte, l)
	for i := 0; i < l; i++ {
		bytes[i] = byte(randInt(65, 90))
	}
	return string(bytes)
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

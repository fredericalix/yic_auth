package main

import (
	"fmt"
	"log"

	"github.com/streadway/amqp"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
		panic(fmt.Sprintf("%s: %s", msg, err))
	}
}

type emailService struct {
	conn *amqp.Connection
	ch   *amqp.Channel
	q    amqp.Queue
}

func newEmailService(rabbitmqHost string) *emailService {
	var err error
	es := &emailService{}
	es.conn, err = amqp.Dial(rabbitmqHost)
	failOnError(err, "Failed to connect to RabbitMQ")

	go func() {
		log.Fatalf("closing: %s", <-es.conn.NotifyClose(make(chan *amqp.Error)))
	}()

	es.ch, err = es.conn.Channel()
	failOnError(err, "Failed to open a channel")

	es.q, err = es.ch.QueueDeclare(
		"email", // name
		true,    // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	failOnError(err, "Failed to declare a queue")

	return es
}

func (es *emailService) SendEmail(emailTo, subject string, content []byte, corrID string) error {
	err := es.ch.Publish(
		"",        // exchange
		es.q.Name, // routing key
		false,     // mandatory
		false,
		amqp.Publishing{
			DeliveryMode:  amqp.Persistent,
			ContentType:   "text/html",
			Headers:       amqp.Table{"To": emailTo, "Subject": subject},
			Body:          content,
			AppId:         "auth_service",
			CorrelationId: corrID,
		})
	return err
}

func (es *emailService) Close() {
	if es.conn != nil {
		es.conn.Close()
	}
	if es.ch != nil {
		es.ch.Close()
	}
}

import pika
import json

def send_rabbitmq_message(message_data, queue_name='modem_queue'):
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))  # RabbitMQ localde
        channel = connection.channel()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=queue_name,
            body=json.dumps(message_data),
            properties=pika.BasicProperties(delivery_mode=2)
        )
        connection.close()
        return True
    except Exception as e:
        print(f"RabbitMQ gönderim hatası: {e}")
        return False

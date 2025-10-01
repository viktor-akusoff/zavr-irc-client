# debug_client.py
import logging
import threading
import time

# Предполагается, что ваш клиент и конфиг находятся в файле client.py
from client import ZavrClient, ClientConfig, ClientServiceMessages

# 1. Настраиваем логирование, чтобы видеть ВСЁ
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
)

# 2. Конфиг для подключения (используйте тестовый сервер)
# Public testnet: irc.ergo.chat:6697 (TLS)
CONFIG = ClientConfig(host="irc.libera.chat", port=6697, tls=True)


def handle_input(client: ZavrClient):
    """Поток для чтения пользовательского ввода и отправки в send_queue."""
    print(
        "Введите IRC-команды для отправки (например, NICK my_test_nick). Введите 'quit' для выхода."
    )
    while True:
        try:
            message = input()
            if message.lower() == "quit":
                break
            client.send_message(message)
        except EOFError:
            break
    client.stop()


def main():
    client = ZavrClient(CONFIG)

    with client:
        # 3. Запускаем поток для пользовательского ввода
        input_thread = threading.Thread(
            target=handle_input, args=(client,), name="InputThread", daemon=True
        )
        input_thread.start()

        # 4. Основной цикл для чтения из очередей
        is_running = True
        while is_running:
            # Неблокирующе проверяем статусы
            status = client.get_status_message()
            if status:
                print(f"[STATUS]: {status.value}")
                if status in [
                    ClientServiceMessages.CONNECTION_ERROR,
                    ClientServiceMessages.SERVER_CLOSED_CONNECTION,
                    ClientServiceMessages.RECEIVER_STOPPED,
                ]:
                    is_running = False  # Завершаем цикл, если соединение умерло

            # Неблокирующе проверяем сообщения от сервера
            message = client.get_message()
            if message:
                print(f"[RECV]: {message}")

            time.sleep(0.1)  # Чтобы не загружать CPU

    print("Клиент остановлен.")


if __name__ == "__main__":
    main()

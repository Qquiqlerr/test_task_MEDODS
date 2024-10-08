# Тестовое задание на позицию Junior Backend Developer

Задание: https://medods.notion.site/Test-task-BackDev-623508ed85474f48a721e43ab00e9916

Этот проект представляет собой часть сервиса аутентификации, реализующий выдачу и обновление JWT и Refresh токенов.

## Функциональность:
1. Генерация пары токенов с привязкой к GUID
2. Обновление пары токенов
3. Проверка IP-адреса при обновлении токенов и отправка предупреждения на email при изменении

## Технологии:

- Go 1.22
- JWT
- PostgreSQL
- Docker и docker-compose

***

# Настройки и запуск
1. Клонируйте репозиторий 
```bash
git clone https://github.com/Qquiqlerr/test_task_MEDODS.git
cd test_task_MEDODS
```
2. Создайте .env файл и заполните его необходимой информацией
```text
DB_HOST
DB_USER
DB_PASSWORD
DB_NAME
SECRET
```

3. Запустите сервис с помощью docker-compose
```bash
docker-compose up --build
```

Сервис будет доступен по адресу `0.0.0.0:80`

***

# API эндпоинты
## 1. `POST /auth/token`
Выдает пару токенов

## Запрос
```json
{
  "guid": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Ответ
```json
{
  "access": "eyJhbGciOiJIUzI1NiIs...",
  "refresh": "eyJhbGciOiJIUzI1NiIs..."
}
```

## 2. `POST /auth/refresh`
Обновляет пару токенов

## Запрос

```json
{
  "access": "eyJhbGciOiJIUzI1NiIs...",
  "refresh": "eyJhbGciOiJIUzI1NiIs..."
}
```
access токен мы передаем в теле запроса учитывая что в дальнейшем он будет находиться в заголовках

## Ответ
```json
{
  "new_access": "eyJhbGciOifvxIUzI1NiIs...",
  "new_refresh": "AScdfsGciOiJIUzI1NiIs..."
}
```

***
# Проблемы и решения

## Проблема:
Связывание двух токенов между собой
## Решение:
При создании пары токенов генерируется уникальный идентификатор сессии(**UUID**). Он добавляется в Payload access-токена и сохраняется в базу вместе с хешем refresh-токена. Таким образом мы можем проверить что refresh и access токены были выданы в рамках одной сессии.

***
## Проблема:
Защита от повторного использования refresh-токена
## Решение:
Замена хеша токена в базе данных по UUID. Убирает возможность повторного использования ключа, а так же позволяет одному пользователю иметь несколько сессий(например на разных устройствах)

***
## Проблема:
Отслеживание IP-адреса
## Решение:
Добавление IP-адреса в Payload access-токена при создании и сравнение с IP-адресом при refresh операции. Если они не совпадают то Payload нового access-токена будет содержать новый IP, а пользователю отправится email-уведомление

# Контакты
* Почта: leha.metlushko@bk.ru
* Telegram: @sslowerr
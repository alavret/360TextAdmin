# Changelog - Email Signature Feature

## Добавленная функциональность

### 1. Новый пункт меню
- В подменю "Work with email settings" (пункт 4 главного меню) добавлен новый пункт "Get email signature" (пункт 6)

### 2. Новые функции

#### `find_user_by_search_term(settings, search_term)`
- Поиск пользователя по логину, email, UID или фамилии
- Параметры:
  - `settings`: объект настроек
  - `search_term`: строка для поиска (логин, email, UID или фамилия)
- Возвращает: объект пользователя или None

#### `get_user_email_signature(settings, user_id)`
- Получение подписи пользователя через API 360
- Параметры:
  - `settings`: объект настроек
  - `user_id`: ID пользователя
- Возвращает: данные подписи (dict) или None
- API endpoint: `/admin/v1/org/{org_id}/mail/users/{user_id}/settings/sender_info`

#### `save_signature_to_file(settings, user, signature_data)`
- Сохранение подписи в файл
- Параметры:
  - `settings`: объект настроек
  - `user`: объект пользователя
  - `signature_data`: данные подписи
- Возвращает: имя созданного файла или None
- Формат файла: `{префикс}{логин}.txt`

#### `get_email_signature(settings)`
- Главная функция для получения подписи пользователя
- Интерактивный интерфейс с использованием Rich
- Отображает подпись в консоли и сохраняет в файл

### 3. Новые переменные среды

#### `EMAIL_SIGNATURE_FILE_PREFIX_ARG`
- Префикс для имени файла с подписью
- Значение по умолчанию: `signature_`
- Пример использования в `.env`:
```
EMAIL_SIGNATURE_FILE_PREFIX_ARG=signature_
```

### 4. Изменения в структуре данных

#### Добавлено поле в `SettingParams`:
```python
email_signature_file_prefix: str
```

## Примеры использования

### Пример 1: Получение подписи по логину
```
Enter user login, email, UID or last name: ivan.petrov
```

### Пример 2: Получение подписи по email
```
Enter user login, email, UID or last name: ivan.petrov@company.com
```

### Пример 3: Получение подписи по UID
```
Enter user login, email, UID or last name: 1130000000000001
```

### Пример 4: Получение подписи по фамилии
```
Enter user login, email, UID or last name: Петров
```

## Формат выходного файла

### Имя файла
`{префикс}{логин_пользователя}.txt`

Например: `signature_ivan.petrov.txt`

### Содержимое файла
Текст подписи пользователя в формате plain text

## Технические детали

### API Endpoint
```
GET /admin/v1/org/{org_id}/mail/users/{user_id}/settings/sender_info
```

### Требования
- OAuth токен с правами на чтение настроек почты пользователей
- Доступ к API Яндекс 360
- Python 3.6+
- Библиотека Rich для красивого вывода

### Обработка ошибок
- Проверка существования пользователя
- Retry механизм для API запросов (до 3 попыток)
- Логирование всех операций
- Красивое отображение ошибок в консоли

## Исправленные ошибки
- Исправлены синтаксические ошибки с кавычками в f-строках по всему файлу
- Улучшена обработка ошибок при API запросах

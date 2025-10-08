# Функция установки подписей для сообщений

## Описание
Добавлена новая функциональность для массовой установки подписей пользователям Яндекс 360 на основе шаблона.

## Использование

### 1. Подготовка файлов

#### Входной файл с пользователями (`users_signature_input.csv`)
```
# Пример входного файла для установки подписей
# Строки, начинающиеся с #, игнорируются
# В каждой строке: алиас, email, id или фамилия пользователя
alavret
ivan.petrov
user@company.com
1130000000000001
Петров
```

#### Шаблон подписи (`signature_template.html`)
```html
<div>-- </div>
<div><em>С Уважением,</em></div>
<div> </div>
<div><span style="font-family:'comic sans ms' , sans-serif;font-size:16px;line-height:normal"><strong>{first} {middle} {last} ❤️</strong></span></div>
<div><blockquote><div><span style="color:#4b0082">email</span>: <a href="mailto:{email}" rel="noopener noreferrer">{email}</a></div></blockquote></div>
<div><blockquote><div>tel: {phone}</div></blockquote></div>
<div><blockquote><div>position: {position}</div></blockquote></div>
<div><a href="https://360.yandex.ru">site</a></div>
<div> </div>
<div><img src="https://avatars.mds.yandex.net/get-yapic/36689/ibZ4wLaL4Vrw5rZRmobgBL2fu0-1/islands-200" /></div>
```

### 2. Запуск функции

1. Запустите скрипт: `python3 360_text_admin_console.py`
2. Выберите пункт меню "Work with email settings" (пункт 4)
3. Выберите "Set email signature" (пункт 7)
4. Укажите путь к файлу с пользователями
5. Укажите путь к шаблону подписи
6. Подтвердите выполнение

## Параметры шаблона

В шаблоне можно использовать следующие переменные:

| Переменная | Описание | Источник |
|------------|----------|----------|
| `{first}` | Имя | `user.name.first` |
| `{middle}` | Отчество | `user.name.middle` |
| `{last}` | Фамилия | `user.name.last` |
| `{position}` | Должность | `user.position` |
| `{email}` | Email адрес | `user.nickname@domain` |
| `{phone}` | Телефон | `user.phone` |

## API Endpoint

Используется endpoint согласно [официальной документации Яндекс 360](https://yandex.ru/dev/api360/doc/ru/ref/MailUserSettingsService/MailUserSettingsService_SetSenderInfo):

```
POST /admin/v1/org/{orgId}/mail/users/{userId}/settings/sender_info
```

### Структура данных запроса:
```json
{
    "signs": [
        {
            "emails": ["user@domain.com"],
            "isDefault": true,
            "text": "HTML подпись",
            "lang": "ru"
        }
    ],
    "signPosition": "bottom"
}
```

## Обработка ошибок

### Валидация пользователей
- Проверка существования каждого пользователя в Яндекс 360
- Обработка множественных совпадений
- Пропуск строк, начинающихся с `#`
- Создание списка проблемных строк

### API вызовы
- Retry механизм (до 3 попыток)
- Логирование всех операций
- Обработка HTTP ошибок
- Статистика успешных/неудачных операций

## Примеры использования

### Пример 1: Простой список пользователей
```
users_signature_input.csv:
alavret
ivan.petrov
user@company.com
```

### Пример 2: С комментариями
```
users_signature_input.csv:
# IT отдел
alavret
ivan.petrov
# Маркетинг
user@company.com
```

### Пример 3: Смешанные форматы
```
users_signature_input.csv:
alavret                    # по логину
ivan.petrov@company.com    # по email
1130000000000001          # по UID
Петров                     # по фамилии
```

## Требования

- OAuth токен с правами на управление настройками почты пользователей
- Доступ к API Яндекс 360
- Python 3.6+
- Библиотека Rich для красивого вывода

## Безопасность

- Подтверждение пользователя перед выполнением операций
- Валидация всех входных данных
- Логирование всех операций
- Graceful обработка ошибок

## Логирование

Все операции записываются в лог-файл `360_text_admin_console.log`:
- Чтение файлов
- Валидация пользователей
- API вызовы
- Результаты операций

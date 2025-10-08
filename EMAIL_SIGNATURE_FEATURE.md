# Email Signature Feature

## Описание
Добавлена новая функциональность для получения подписи пользователя из Яндекс 360.

## Использование
1. Запустите скрипт `360_text_admin_console.py`
2. Выберите пункт меню "Work with email settings" (пункт 4)
3. Выберите "Get email signature" (пункт 6)
4. Введите логин, email, UID или фамилию пользователя
5. Подпись будет отображена в консоли и сохранена в файл

## Настройка
Добавьте в файл `.env` переменную:
```
EMAIL_SIGNATURE_FILE_PREFIX_ARG=signature_
```

По умолчанию используется префикс `signature_`.

## Формат файла
Файлы подписи сохраняются в формате: `{префикс}{логин_пользователя}.txt`

Например: `signature_ivan.petrov.txt`

### Содержимое файла
```
Email Signatures for ivan.petrov
==================================================

Signature 1:
  Language: ru
  Default: true
  Emails: ivan.petrov@company.com
  Text:
С уважением,
Иван Петров
IT отдел
------------------------------

Signature 2:
  Language: en
  Default: false
  Emails: ivan.petrov@company.com
  Text:
Best regards,
Ivan Petrov
IT Department
------------------------------
```

## API Endpoint
Используется endpoint: `/admin/v1/org/{org_id}/mail/users/{user_id}/settings/sender_info`

## Структура данных API
Согласно [официальной документации Яндекс 360](https://yandex.ru/dev/api360/doc/ru/ref/MailUserSettingsService/MailUserSettingsService_GetSenderInfo), API возвращает:

```json
{
    "fromName": "string",
    "defaultFrom": "string",
    "signs": [
        {
            "emails": ["string"],
            "isDefault": false,
            "text": "string",
            "lang": "string"
        }
    ],
    "signPosition": "bottom"
}
```

Где:
- `signs` - массив подписей пользователя
- `text` - текст подписи (поддерживает HTML)
- `lang` - язык подписи
- `isDefault` - является ли подписью по умолчанию
- `emails` - привязанные email адреса

## Требования
- OAuth токен с правами на чтение настроек почты пользователей
- Доступ к API Яндекс 360

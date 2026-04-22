## VLESS Parser (актуализированная версия)

Скрипт собирает публичные VLESS-ссылки из Telegram-каналов, форумов и GitHub-агрегаторов, парсит их в формат `proxies` для Clash и сохраняет YAML.

### Что улучшено

- поддержка `sources.yaml` в двух форматах: `string` и `object` (`url` + `tag`);
- извлечение VLESS из обычного текста и из Base64-подписок;
- более строгая валидация UUID и портов;
- поддержка популярных полей VLESS: `tls`, `reality-opts`, `ws-opts`, `grpc-opts`, `h2-opts`, `alpn`, `servername`, `flow`;
- дедупликация по ключевым параметрам узла;
- метаданные генерации (`generated_at`, `count`) в выходном файле.

### Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Запуск

```bash
python parse_vless.py --sources sources.yaml --output proxies.yaml
```

### Примечания

- Источники публичные и нестабильные: часть ссылок может быть недоступна или временно пустая.
- Скрипт продолжает работу, даже если некоторые источники вернули ошибку.

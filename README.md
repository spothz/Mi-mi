# Mi-mi

Парсер VLESS (XTLS/Reality/WS/GRPC) из открытых источников для генерации секции
`proxies:` в формате Clash YAML.

## Подписка для Clash через GitHub

1. Запушьте репозиторий на GitHub.
2. Включите GitHub Actions.
3. Дождитесь выполнения workflow `Update VLESS proxies` (или запустите вручную).
4. Используйте ссылку на `proxies.yaml` как подписку:

   ```
   https://raw.githubusercontent.com/<USER>/<REPO>/main/proxies.yaml
   ```

Workflow обновляет `proxies.yaml` каждые 6 часов и пушит изменения в репозиторий.

## Быстрый старт

1. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
2. Обновите список источников в `sources.yaml`.
3. Запустите:
   ```bash
   python parse_vless.py --sources sources.yaml --output proxies.yaml
   ```

Файл `proxies.yaml` содержит секцию `proxies:` для последующего использования в
Clash.

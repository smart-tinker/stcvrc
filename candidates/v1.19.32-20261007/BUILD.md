# Воспроизводимая сборка review-кандидата

Это рецепт **только для кандидата**, не релиз и не разрешение установки.
Корневой `build-windows.ps1` по-прежнему закреплён на принятом релизе;
его guard и release workflows не изменяются.

## Закреплённые входы

- Публичный repository: `https://github.com/smart-tinker/stcvrc`.
- Source commit: `3d0127d8cc24a6d6c10f7063dad4e0fd97565432`.
- Source tree: `f5541fdebd99b877619656e54a16f1b3c8a20d03`.
- Это опубликованный snapshot исходников local candidate `792d4c3e`,
  а не требование иметь его непубличную Git history.
- Toolchain: Windows amd64 **Go 1.26.5**, не автоматически скачиваемая версия.
- Архив: `go1.26.5.windows-amd64.zip`, SHA-256
  `97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38`.
- `go.exe` из использованного архива: SHA-256
  `d6a71e6dc9806cb3f1fcb817d562175c5a7b1505fc3f6638299648e0b9f0f74f`.
- Version: `1.19.32-STCVRC-candidate-20261007`.
- BuildTime: `2026-10-07T00:00:00Z` (фиксированная метка, не время запуска).
- Target: `GOOS=windows`, `GOARCH=amd64`, `GOAMD64=v1`, `CGO_ENABLED=0`.
- Flags: `-mod=readonly -tags with_gvisor -trimpath -buildvcs=false`,
  linker `-s -w -buildid=` и два фиксированных `-X` ниже.
- Dependencies: закреплённые `go.mod`/`go.sum` этого source commit.

Рецепт экспортирует **именно этот commit** через `git archive` в новую папку:
последующие documentation/test commits в PR и локальные working-tree changes
в сборку не попадают. Если код кандидата изменится, нужно отдельно обновить
pin/ожидаемый digest; этот скрипт не проверяет произвольный текущий `HEAD`.

## Запуск на Windows

Нужны Git, Windows PowerShell 5.1 или новее и указанный Go.
Скачать архив toolchain можно с [go.dev](https://go.dev/dl/).
Распаковать его после проверки SHA-256; скрипт также проверяет digest `go.exe`
и точный вывод `go version`.

```powershell
git clone --branch review/uservm-candidate-20261015 https://github.com/smart-tinker/stcvrc.git
cd stcvrc

# Пример: toolchain распакован в C:\Tools\go1.26.5\go.
# Выберите новую output-папку ВНЕ checkout; существующая папка отвергается.
.\candidates\v1.19.32-20261007\build-candidate.ps1 `
  -GoExe C:\Tools\go1.26.5\go\bin\go.exe `
  -WorkRoot C:\Build\stcvrc-candidate-20261007
```

Полный clone содержит pinned commit. При shallow clone получите его явно:

```powershell
git fetch origin 3d0127d8cc24a6d6c10f7063dad4e0fd97565432
```

Сборка использует новый `GOCACHE` и отключает пользовательские Go settings,
workspace, telemetry и автоматическую замену toolchain. По умолчанию зависимости
скачиваются с `proxy.golang.org`/direct и проверяются `go.sum`/sum.golang.org;
`go.mod`/`go.sum` не обновляются. Для уже заполненного module cache:

```powershell
.\candidates\v1.19.32-20261007\build-candidate.ps1 `
  -GoExe C:\Tools\go1.26.5\go\bin\go.exe `
  -WorkRoot C:\Build\stcvrc-candidate-offline `
  -ModuleCache C:\Build\gomodcache -Offline
```

`-Offline` выставляет `GOPROXY=off` и `GOSUMDB=off`; отсутствующие зависимости дают ошибку,
а не заменяются. Системные настройки/сервисы и исходный checkout не меняются.
Указанные пути — примеры, не project-specific данные.
Для ускорения повторного прогона можно явно передать `-BuildCache` с существующим
Go build cache; по умолчанию используется новая папка `WorkRoot/gocache`.

Эквивалентный build invocation в экспортированной папке исходников:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:GOAMD64 = 'v1'
$env:CGO_ENABLED = '0'
$env:GOFLAGS = '-mod=readonly'
go build -tags with_gvisor -trimpath -buildvcs=false `
  -ldflags '-s -w -buildid= -X "github.com/metacubex/mihomo/constant.Version=1.19.32-STCVRC-candidate-20261007" -X "github.com/metacubex/mihomo/constant.BuildTime=2026-10-07T00:00:00Z"' `
  -o verge-mihomo.exe .
```

Для полного fail-closed environment/export/hash check используйте скрипт,
а не только эту сокращённую команду.

## Критерий воспроизведения

Результат: `out/verge-mihomo.exe`, **61 108 736 bytes**.
Ожидаемый SHA-256:

```text
b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986
```

`-v` должен вернуть:

```text
Mihomo Meta 1.19.32-STCVRC-candidate-20261007 windows amd64 with go1.26.5 2026-10-07T00:00:00Z
Use tags: with_gvisor
```

Скрипт завершает работу ошибкой при ином source tree/toolchain/hash/version,
сохраняет без приватных путей `build-report.json` рядом с output и восстанавливает
process environment после сборки. Вызов `-v` не запускает прокси runtime.

`build-report.json` в этой папке — результат реального повторного прогона
из публичного snapshot, а не ожидаемый/синтезированный вывод.
15.10.2026 две такие сборки дали этот же SHA: cold-cache прогон завершился
в `11:43:31Z`, окончательный рецепт с warm cache и явными
`GOPROXY=off`/`GOSUMDB=off` — в `11:46:08Z`. Дополнительно проверены
PowerShell parser, отказ до экспорта при неверном toolchain digest и отказ
перезаписывать существующий `WorkRoot`.
Build recipe сам **не запускает тесты**: отдельный PUSH_REQUEST retry test и
остальные source tests имеют свои отчёты. Совпадение SHA не означает VM/TUN,
full-stack rollback или приёмку Home/Work; эти ворота остаются закрыты.

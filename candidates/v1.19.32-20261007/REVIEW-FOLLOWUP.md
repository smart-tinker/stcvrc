# PR #2 — ответы на замечания проверки

Это материалы к [ревью Оскара](https://github.com/smart-tinker/stcvrc/pull/2#issuecomment-6190995095),
не выпуск и не разрешение установки. Исполняемые исходники core не изменялись.
Проверяемый публичный snapshot: `3d0127d8cc24a6d6c10f7063dad4e0fd97565432`.

## 1. Пропущенный PUSH_REQUEST retry

На чистом checkout указанного snapshot выполнено:

```text
go test -json -v -tags with_gvisor -count=1 -timeout=90s ./transport/openvpn -run '^TestInitialHandshakeRetriesDeferredPush$'
```

Go 1.26.5, offline dependency cache, exit 0. Тест PASS (3.51s):
`silent` (1.01s), `auth-pending` (1.00s), `continuation` (1.50s).
Пакет завершился за 5.639s. `-json -v` добавляют проверяемый вывод;
маска, теги, `-count=1` и timeout соответствуют запросу ревью.
[Отчёт](push-retry-report.json), [фактический Go test JSON](push-retry.jsonl).
Это in-memory/mock handshake, не live VPN/сетевая приёмка.

## 2. Проверяемая подготовка отката и observer

[Исходники, инструкция и границы](preparation/README.md),
[provenance и original/public SHA-256](preparation/provenance.json),
[обезличенный diff адаптации](preparation/sanitization.patch),
[свежий отчёт подготовки](preparation/evidence/preparation-tests.json).

Опубликованы обезличенные копии настоящих скриптов и тестов с зависимостями,
а не альтернативная реализация отката. Прежние девять source hashes отдельно
сверены; для каждого public файла указан собственный hash и изменения.
Приватные идентификаторы заменены фикстурами; host/SID/path guards сохранены.
Эти копии предназначены для source review и offline tests, не для развёртывания.

Свежий прогон этих копий с настоящими pinned core/installer inputs:
55 PASS, 0 failures/errors/skips. Бинарники только читаются для проверки SHA-256,
не исполняются и не публикуются. Без exact artifacts runner честно показывает
54 PASS и 1 SKIP: полная воспроизводимость всех 55 требует указанных в инструкции
входных файлов. Неправильные переданные bytes должны давать FAIL.

Эти проверки покрывают unit/fixtures/PowerShell AST и version/hash guards.
Они **не доказывают** реальную установку или восстановление Windows/runtime.
Наличие installer observer не означает готовность atomic observer rollback.

Дополнительный observer source suite сначала дал 72 PASS / 1 FAIL
(`test_active_checks_do_not_run_each_minute`). Первый результат сохранён:
[JSON](preparation/evidence/observer-first-run.json),
[лог](preparation/evidence/observer-first-run.txt).
[Диагностика](preparation/evidence/observer-fixture-diagnostic.json) воспроизвела
причину: немокированный `host_view` занял 25.251s при stage budget 25s;
шесть probes получили budget/deadline UNKNOWN вместо вызова mock. В публичной
тестовой копии изолирована только эта host fixture; изменение отмечено в
provenance/diff, production collector не менялся. После этого полный набор:
[73 PASS](preparation/evidence/observer-tests.json). Это исправление изоляции
локального теста, не доказательство runtime/TUN/recovery.

## 3. Воспроизводимая сборка кандидата

[BUILD.md](BUILD.md) описывает pinned source/toolchain и команды;
[build-candidate.ps1](build-candidate.ps1) отдельно от неизменённого release guard
экспортирует immutable public snapshot, задаёт target/flags/version/time и
fail-closed проверяет итоговый SHA-256. [Фактический build report](build-report.json)
документирует результат новой сборки. Её SHA совпал с existing candidate:

```text
b072d09f0754b92cbe737757d2c63111d20ecf00e5d90b534ce2f9492feb9986
```

Recipe собирает pinned snapshot, а не подмешивает dirty working files или будущие
commits с документацией. Сборка и `-v` не запускают proxy/service и не являются
runtime acceptance. В этом PR binary/release assets не публикуются.

## Границы, которые не закрыты этим follow-up

- Candidate TUN/recovery и atomic observer + UI/core rollback не готовы.
- Work-host deployment не принят; offline version pair не заменяет host support.
- Shared userVM занята; новых VM/SSH/сетевых испытаний, reboot и восстановления не было.
- После освобождения требуется отдельное окно и свежий baseline/backup, чтобы
  не затереть позднейшие изменения; затем exact-version full-stack/reboot/logon,
  SYSTEM deadline rollback и cleanup comparison.
- Home/Work-ready — **NO**. Merge/release/rollout не выполнялись и не разрешены
  этими материалами; последующие окна согласуются отдельно.

Пробелы проверки не объявляются доказательством неисправности кандидата.

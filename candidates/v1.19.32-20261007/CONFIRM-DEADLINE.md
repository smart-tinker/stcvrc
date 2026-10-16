# PR #2 — deadline перед commit отката

Ответ на [повторное ревью](https://github.com/smart-tinker/stcvrc/pull/2#issuecomment-6191897311).
Это узкое исправление transaction guard и его offline regression, не результат
испытания Windows/runtime. Сбоя на Home/Work не наблюдали и не утверждаем.

## Риск и исправление

Начальная проверка deadline не ограничивает суммарную длительность последующих
health probes. Если они завершились успешно, но после deadline, прежний Confirm
мог опубликовать `committed`; тогда Watch считал transaction завершённым и не
выполнял восстановление. Это вывод из кода и детерминированного сценария.

После успешных health probes перед публикацией `committed` UTC deadline
проверяется повторно с прежним 15-second safety margin. При
`now >= deadline - 15s` commit запрещён. Health probes выполняются без
удержания transaction lock, чтобы не задерживать независимый Watch rollback.
После probes Confirm снова захватывает lock и перечитывает phase, armed hash
и plan hash; уже начатое/завершённое восстановление либо transaction drift
не может быть перезаписано `committed`. Ошибка health probe также не публикует
`committed`. Допустимый до margin happy path сохраняется.
Это cooperative safety gate, не hard-realtime гарантия: короткая критическая
секция всё равно содержит файловый I/O; произвольное зависание ОС этим не
исключается. Интеграционная проверка Watch/recovery на VM остаётся обязательной.

Вызовы реальной VM, сети, services, installers, scheduled tasks и real restore
в этой проверке отсутствуют. Regression исполняет настоящий Confirm AST и
настоящий локальный transaction file lock; `Get-Date`/health/state/restore
подставлены synthetic dependencies. Два health шага по 9s продвигают
детерминированные часы без реального ожидания. Сценарий Watch исполняет
actual Watch AST с synthetic boot mismatch; его static clock не подменяется.
`Restore-Old` и системные операции заменены фикстурами. Это проверяет
availability lock и control flow запрета/восстановления, не реальный
wall-clock deadline recovery Windows.

## Проверяемые исходники и provenance

- [Исправленная обезличенная копия actual transaction](preparation/scripts/stcvrc-safe-rollout.ps1).
- [Regression source](preparation/scripts/test_stcvrc_confirm_deadline.py).
- [Current original/public SHA-256 и исторические hashes](preparation/provenance.json).
- [Обезличенный diff адаптации копий](preparation/sanitization.patch).

Это 25 source maps: прежние 24 и один новый regression module. Из прежних
оригиналов 23 не изменились; единственная намеренная production-source delta —
`stcvrc-safe-rollout.ps1`. Девять hashes прогона 13:12 МСК были сверены 9/9
в [предыдущем commit](https://github.com/smart-tinker/stcvrc/tree/162c7fe5c21258146b806a65b5602ae52021a572/candidates/v1.19.32-20261007).
После исправления текущие оригиналы совпадают с ними 8/9, не 9/9. Прежние
значения не перезаписаны: `historicalOriginalSha256` и `historicalPublicSha256`
связаны с этим commit, current `originalSha256`/`publicSha256` — с исправлением.

Старые результаты preparation55, observer73, retry и reproducible build
сохранены как исторические материалы предыдущего commit, не как новая
проверка изменённого guard. Core/observer/installer binaries, core source,
build recipe и release guard не менялись; новая сборка core не нужна.
Уже созданные immutable staged transactions не исправляются задним числом:
новый source/script hash попадёт только в новую подготовленную transaction.
Старую transaction нельзя объявить исправленной по изменению исходного файла.

## RED/GREEN и свежие проверки

- До исправления: [реальный RED log](preparation/evidence/confirm-deadline/regression-red.txt),
  [report](preparation/evidence/confirm-deadline/regression-red-report.json).
  Детерминированный сценарий ожидал запрет commit после health overshoot;
  прежний код ошибочно подтвердил transaction. Это намеренно failing regression.
- После исправления: [GREEN log](preparation/evidence/confirm-deadline/regression-green.txt),
  [report](preparation/evidence/confirm-deadline/regression-green-report.json).
- На финальных public sanitized copies весь preparation runner:
  **66 PASS, 0 failures/errors/skips**, 32.378 s:
  [JSON](preparation/evidence/confirm-deadline/preparation-tests.json),
  [лог](preparation/evidence/confirm-deadline/preparation-tests.txt).
  Это прежние 55 cases плюс 11 cases нового regression module.
- Без binaries: **65 PASS + 1 SKIP**, 32.243 s:
  [JSON](preparation/evidence/confirm-deadline/source-only/preparation-tests.json),
  [лог](preparation/evidence/confirm-deadline/source-only/preparation-tests.txt).
  Пропущен только exact-artifact hash case, regression cases выполнены.
- SHA-256 всех 25 public source inputs совпали с финальным provenance до запуска.
  Full artifacts были только прочитаны для SHA-256; binary execution отсутствует.


Первый новый full invocation попал в system Python без `PyYAML`: 33 cases,
30 PASS и 3 module-import ERROR (`No module named 'yaml'`); regression11
уже прошла. [Лог](preparation/evidence/confirm-deadline/environment-first-run/preparation-tests.txt)
и [JSON](preparation/evidence/confirm-deadline/environment-first-run/preparation-tests.json)
сохранены. Это ошибка dependency-контекста запуска, не сигнал неисправности
candidate. Финальный прогон — Python3.13.13 с уже имеющимися PyYAML6.0.2 и
psutil6.1.1; процесс-local `PYTHONPATH`, без установки и изменения global env.

## Независимое воспроизведение

Windows x64, Windows PowerShell 5.1, Python 3.13; зависимости закреплены в
[requirements.txt](preparation/requirements.txt). Из корня checkout:

```powershell
$prep = '.\candidates\v1.19.32-20261007\preparation'
$scratch = Join-Path $env:LOCALAPPDATA 'stcvrc-review\scratch'
py -3.13 -B "$prep\run_preparation.py" --work-dir $scratch --output-dir "$prep\evidence\confirm-deadline\source-only"
py -3.13 -B "$prep\run_preparation.py" --work-dir $scratch --artifacts-root '<root>' --output-dir "$prep\evidence\confirm-deadline"
```

Без pinned binaries пропускается ровно один artifact-hash case, а не весь
regression; это не полный PASS. При явном `--artifacts-root` отсутствие либо
ошибка bytes даёт ERROR/FAIL. [Точные paths и hashes](preparation/README.md).
Бинарники только читаются для SHA-256, не исполняются. Runner проверяет
provenance public hashes и отклоняет Python socket connect/getaddrinfo/bind.
Counts — unittest cases; вложенные regression vectors перечислены в логе.

## Приёмка и оставшиеся ограничения

**Home/Work-ready NO.** Новые VM/TUN/recovery/reboot/logon/cleanup tests не
проводились: shared userVM занята. После её освобождения нужны отдельное окно
и свежий baseline/backup, затем exact-version full-stack/deadline recovery,
cleanup comparison, authenticated consumer и independent management gates.
Atomic observer + UI/core rollback и Work-host deployment остаются открытыми.
Merge, release, installation и production rollout этим исправлением не разрешены.

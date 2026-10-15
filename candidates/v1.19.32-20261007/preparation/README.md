> Rollback follow-up: [исправления и актуальная проверка](../OBSERVER-RECOVERY.md). VM/runtime recovery не принято.

> Актуальное продолжение: [candidate TUN и общий rollback](../PREPARATION-NEXT.md). Ниже сохранено описание предыдущих прогонов; текущие source hashes — в provenance.json. Runtime gates остаются открыты.

# Текущее уточнение: confirm deadline

[Повторное ревью и исправление](../CONFIRM-DEADLINE.md): текущий guard
имеет post-health deadline check и не держит lock во время health probes.
Свежие финальные public copies: **66 PASS** с pinned artifacts,
**65 PASS + 1 SKIP** без них. Это 55 прежних и 11 новых
cases; runtime/TUN/recovery и Home/Work acceptance по-прежнему NOT_RUN/NO.
Материалы первого follow-up ниже явно сохранены как historical.

# Локальная проверка подготовки отката и observer

Это проверяемая обезличенная копия существующих project-owned scripts, а не
новая реализация rollback и не готовый deployment bundle. Один оригинал guard исправлен после повторного ревью; historical hashes
сохранены в provenance, прочие 23 прежних оригинала неизменны. Не запускайте entry points из `scripts/` для установки: host,
account, SID и canary endpoints в этой копии заменены fixture-значениями.
Запускается только `run_preparation.py`.

## Что включено

- Actual UI/core transaction `stcvrc-safe-rollout.ps1`, preparation helper,
  history-preservation helper, desktop/installer/layout/cleanup harness source.
- Actual `stcvrc_observer.py`, его source tests, observer installer и необходимые
  Python dependencies проекта. Фикстуры находятся непосредственно в тестах;
  private profiles и исходные runtime logs не требуются и не включены.
- Пять original preparation test modules (55 test cases), новый regression module (11 cases) и отдельный существующий
  observer source suite. Подробные test IDs и результаты — в `evidence/`.
- `provenance.json`: original SHA-256 → public path/SHA-256 для каждого файла;
  ровно девять original hashes из исторического прогона отмечены
  `inOriginalNine: true`. До исправления они совпали9/9; сейчас8/9: guard
  намеренно исправлен. Старые hashes и previous commit сохранены отдельно.
  Остальные dependency hashes зафиксированы свежим проходом; исторический
  manifest не содержал их, поэтому он не доказывает неизменность всех inputs.
- `sanitization.patch`: построчный diff, но private original values перед diff
  заменены `<REDACTED_NN>`. Точные private tokens намеренно не публикуются;
  их hashes и число замен доступны в provenance.

## Исторический результат 15.10.2026 до deadline fix

Ниже — результаты commit `162c7fe5`, не финальных текущих inputs.

- Preparation: **55 PASS, 0 failures/errors/skips**, 21.560 s; с real candidate
  installer/core только для SHA-256, без их исполнения.
- Source-only: **54 PASS + 1 SKIP**, 20.259 s; именно отсутствие optional
  binaries, не скрытый PASS. Явный пустой artifacts root отдельно дал ожидаемый
  ERROR на одном artifact test, 0 SKIP: gate не обходится.
- Дополнительный observer source suite: сначала **72 PASS + 1 FAIL**
  (`observer-first-run.*`), затем **73 PASS, 0 failures/errors/skips**, 57.939 s.
  Первый failed run не удалён. Это один source module, не прежний combined
  observer/process/summary/installer прогон из 92 tests.
- Диагностика воспроизвела причину failing scheduling fixture: настоящий
  `host_view` занял **25.251 s** при stage budget **25 s**, поэтому шесть checks
  получили `budget-or-deadline`/UNKNOWN, actual probes = 0. Следующий вызов
  был throttled. Результат — `observer-fixture-diagnostic.json`; это
  дополнительное воспроизведение, не измерение первого failed invocation.
- В public `test_stcvrc_observer.py` изолирован только unrelated `host_view`
  внутри `active_fixture`. Actual collector и deadline не менялись; отдельные
  host tests сохранены. Эту test-only delta видно в provenance/patch.
- Проверено: все 24 оригинальных project files остались неизменны;
  девять исторических hashes совпали; public hashes и private identity/secret
  smoke check прошли (`source-publication-check.json`).

После test-only isolation повторены оба preparation variants, чтобы hashes
в финальных reports механически совпадали с финальным provenance всех 24 files.
Actual collector source SHA-256 одинаков до и после isolation; менялась только
тестовая фикстура. Execution environment: Python 3.13.13, PowerShell
5.1.26100.9549, PyYAML 6.0.2, psutil 6.1.1.

## Независимое воспроизведение

Требуются Windows x64, Windows PowerShell 5.1 и Python 3.13. Использованные
Python dependency versions закреплены в `requirements.txt`. Подготовьте их
в собственном isolated Python environment; runner ничего не устанавливает,
не скачивает, не обращается к VM и не запускает installers/core binaries.

Из корня checkout:

```powershell
$prep = '.\candidates\v1.19.32-20261007\preparation'
$scratch = Join-Path $env:LOCALAPPDATA 'stcvrc-review\scratch'
py -3.13 -B "$prep\run_preparation.py" --work-dir $scratch
py -3.13 -B "$prep\run_preparation.py" --suite observer --work-dir $scratch
```

Для отдельной диагностики unisolated host I/O на synthetic app/API fixtures:

```powershell
py -3.13 -B "$prep\diagnose_observer_fixture.py" --work-dir $scratch
```

Она только читает local host inventory; body probes/API заменены fixtures.
На быстром host deadline может не исчерпаться — это не отрицание сохранённого
измерения. Динамические результаты намеренно не обещаются bit-for-bit.

Текущий первый вызов без binaries честно даёт **65 PASS + 1 SKIP**, а не 66 PASS.
Пропускается только `test_candidate_pins_exact_258_artifacts`.
Для полного прогона дополнительно передайте `--artifacts-root <root>`.
Внешний `<root>` должен содержать два файла по pinned relative paths:

```text
local/artifacts/stcvrc-next-20261015/Clash.Verge_2.5.8_x64-setup.exe
local/artifacts/stcvrc-next-20261007/mihomo-v1.19.32-stcvrc-20261007.exe
```

Точные hashes остаются в `scripts/stcvrc_lab_stack.py` и candidate manifest.
Проверяется реальное SHA-256 содержимого, без mock/replacement hashes.
Отсутствующий либо неверный файл при явном `--artifacts-root` — ошибка теста,
не SKIP. Эти файлы только читаются и никогда не исполняются. Installer
получается из official CVR 2.5.8 release; сборка core описана отдельно в
candidate build instructions. Бинарники не включены в этот source bundle.

```powershell
py -3.13 -B "$prep\run_preparation.py" --work-dir $scratch --artifacts-root '<root>'
```

Runner сверяет public source hashes с provenance до запуска, сохраняет JSON
и текстовый протокол в `evidence/` (можно задать `--output-dir`) и отклоняет
Python socket connect/getaddrinfo/bind. PowerShell checks выполняют извлечённые
AST-функции с fixture dependencies; deployment entry points не исполняются.

## Что доказывают тесты

- Точные UI-пары 2.5.2→2.5.5, 2.5.2→2.5.8, 2.5.5→2.5.8 и fail-closed guard.
- Home-generation approved/owner runtime против legacy Work-generation layout,
  source core readback, UI downgrade layout, owner-runtime checkpoints.
- Staging synthetic profiles/selectors, immutable inputs, metadata preservation,
  approved-copy helper argument/hash contract, bounded mocked installer handling,
  SYSTEM guard/watch-ready ordering и confirmation/deadline conditions.
- Installer target/ACL/task/history-preservation boundaries, desktop acceptance
  bookkeeping, observer sampling/resource/UNKNOWN and source parser behavior.
- Отдельный source observer suite проверяет actual collector на local fixtures;
  это не integration-проверка service logs/TaskScheduler на целевой машине.

Статические/AST checks не доказывают успешное выполнение полного transaction.
Fixture tests не являются новыми реальными профилями или результатами canary.

## Ворота остаются закрытыми

**NOT ACCEPTED:** candidate TUN/dataplane/recovery; atomic observer+UI/core
rollback; Work production host rollout; full-stack VM install/reboot/logon,
deadline rollback и cleanup; authenticated consumer/independent management gate;
Home/Work readiness. Занятую VM не трогали. Старые version-bound PASS не
переносятся на новый комплект. Перед будущим отдельным VM-окном нужен свежий
baseline: текущая проверка не разрешает восстановление старого состояния.

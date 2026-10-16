> Текущее уточнение ownership race: [OBSERVER-DIRECTORY-CLAIM.md](OBSERVER-DIRECTORY-CLAIM.md). Ниже сохранён исторический отчёт.

> Текущий статус: в этом source найдены два rollback-дефекта. Исправления и новое evidence: [OBSERVER-RECOVERY.md](OBSERVER-RECOVERY.md). Ниже сохранён исторический отчёт92 PASS; он не покрывал оба полных failure paths.

# Подготовка candidate TUN и общего отката observer + UI/core

Дата: 2026-10-15T15:32:52.153704+00:00. **OFFLINE 92 PASS; VM gate NOT RUN; Home/Work-ready NO.**

## Зависимость userVM

Координатор сообщил о завершении другой приёмки. Старое «userVM занята»
больше не blocker. Свежий read-only pinned SSH: 10/10 first-attempt PASS,
max 1.931 s, один boot; сняты 8 baseline-категорий.
Это не full backup, exclusive reservation или runtime acceptance. В снимке
остался unrelated GUI-driver; завершённую приёмку по одному процессу не объявляем
активной, чужие процессы не останавливаем. Перед любым испытанием — новый
same-context preflight/backup и фактическая доступность, не сентябрьский restore.

## Реализовано и проверено локально

- Exact candidate2.5.8/core1.19.32 для обеих source-generation пар; прежний
  bounded core-only gate сохранён. TUN включается только под живым SYSTEM
  Watch с exact action/worker/owner/boot/plan/deadline checks. Final recheck
  и PATCH сериализованы transaction lock; probes lock не удерживают.
  Каждый selector PUT также берёт этот lock и повторяет guard check: после
  завершённого Watch rollback поздняя leaf-проба не может изменить baseline.
- Recovery привязан к конкретному успешному probe и свежему route/DNS/
  selector baseline; проверяется возврат old UI/core generation.
- Opt-in observer в общей UI/core transaction: pinned old/new payload,
  exact task configuration, captured absence или fresh old root/task snapshot.
  Проверяются ACL executable files/dirs, owner и schedule. Partial payload
  update восстанавливается; историю data не откатываем и не удаляем.
- Candidate-Check/Confirm требуют completed successful observer task и
  fresh matching completed record, а не только наличие task/manifest.
- Ошибка optional observer не блокирует попытку вернуть core/UI. При неполном
  observer restore итог rollback-incomplete/FAIL, guard остаётся, committed/
  global rolled-back не публикуется. Сохранённый task не доказывает, что
  новый recovery worker уже работает. Реальный retry/Task Scheduler gate открыт.
- Combined VM harness проверяет nested stage hashes, fresh observer sample,
  общий timeout rollback, затем архивирует evidence и удаляет только точный
  run-owned остаток old-absent observer. Для existing observer baseline live
  harness fail-closed; его old-present recovery пока проверен offline.
- CLI regressions исполняют только parser AST prefix: разрешённая новая
  комбинация не может случайно запустить deployment entrypoint из теста.

## Evidence

- [Общий runner: 92 PASS, failures/errors/skips0](preparation/evidence/preparation-next/preparation-tests.json).
- TUN cases: 15; observer transaction: 11;
  Confirm/Watch regression: 11. Это unittest cases, не сумма subtest vectors.
- [Полный лог](preparation/evidence/preparation-next/preparation-tests.txt),
  [provenance: 28 current maps](preparation/provenance.json).
- [TUN RED на прежнем helper](preparation/evidence/preparation-next/tun-red-candidate.txt).
- Финальный независимый review нашёл отдельный selector PUT race после Watch.
  [Детерминированный RED](preparation/evidence/preparation-next/selector-race-red.txt),
  [GREEN](preparation/evidence/preparation-next/selector-race-green.txt).
  Первый общий прогон91 PASS был до этой новой регрессии и не заменяет её.
- [Observer RED на сохранённых before-inputs](preparation/evidence/preparation-next/observer-red.log),
  [targeted GREEN](preparation/evidence/preparation-next/observer-green.log).
  RED воспроизведение сохранённых inputs выполнено отдельно от текущего общего GREEN.
- Python 3.13.13; существующие pinned PyYAML6.0.2/psutil6.1.1;
  dependency installation не выполнялась. Артефакты читались только для SHA-256.
  В тестах реальные source functions/AST/file I/O/lock; OS/task/health/clock —
  явные fixtures. Не выдаём это за Windows recovery или network dataplane.

Runner: `python -B preparation/run_preparation.py --work-dir C:/review-scratch --artifacts-root <external-artifacts-root>`.
Без exact binaries существующий artifact adapter покажет SKIP; полный результат
выше относится к прогону с binaries. Старые reports55/66 сохранены как historical,
их source hashes не являются текущими. Core source/binary/build recipe не менялись.

## Открытые gates

Live exact-version integration, TUN/dataplane/recovery, SYSTEM deadline и
Task Scheduler import/readback, concurrent process recovery, reboot/logon,
observer old-present integration и точный final cleanup/baseline comparison
ещё не приняты. Work-host deployment отдельно не добавлен. Старые immutable
staged transactions не hotpatch: нужен новый staging/hash. Home/Work не обновляем;
PR draft, без merge/release/production rollout.

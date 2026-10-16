# Observer: exclusive directory claim before payload write

Дата: 2026-10-15T23:30:12.366537+00:00. Source follow-up к a6a4d0a1.
**Offline 108 PASS; failures/errors/skips0; 3 новых regression cases.**
VM/runtime acceptance НЕ выполнена; Home/Work-ready NO.

## Закрываемая гонка

В a6a4d0a1 чужой root мог появиться после проверки отсутствия. Следующий Test-Path
пропускал создание собственного root/claim, но Copy-ObserverPayload всё равно
перезаписывал его файлы до проверки collision task. Для empty-baseline установки
payload write теперь требует успешного захвата собственного root/claim. Каталог
с маркерами и защищённым ACL сначала готовится внутри transaction root, затем
Directory.Move захватывает конечный путь без замены существующего каталога.
При collision Move завершается ошибкой; fallback-копирования нет. Receipt
пишется только после успешного Move, перед payload проверяется Assert-ObserverClaim.
Существующий root не принимается за принадлежащий текущей транзакции.

Полный offline Apply → rollback проверяет появление чужого каталога в указанном
окне и сохранение его payload files, manifest, task и history. Конфликт не означает
успешный rollback: FAIL и guard сохраняются. Restore-Old фиксирует
rollback-incomplete; внешний catch полного Apply сохраняет его FAIL result,
но меняет phase на rollback-failed согласно прежнему контракту. Восстановление
observer при HTTP/core errors остаётся независимым; прежний source finding по
этому порядку закрыт координатором. Fixture PASS не заменяет native VM acceptance.

## Фактическое evidence

- [Полный Windows-host offline runner](preparation/evidence/observer-directory-claim/preparation-tests.json): 108 PASS.
- [Лог всех cases](preparation/evidence/observer-directory-claim/preparation-tests.txt).
- [Actual RED on prior source](preparation/evidence/observer-directory-claim/regression-red.txt).
- [Current original/public SHA256 maps](preparation/provenance.json): 29 maps;
  27 прежних originals не изменены.

Новые cases (точные IDs из фактического report):

- `test_stcvrc_observer_recovery_failures.ObserverRecoveryFailureTest.test_foreign_directory_after_last_absence_check_is_preserved_by_apply_and_rollback` — PASS.
- `test_stcvrc_observer_recovery_failures.ObserverRecoveryFailureTest.test_full_apply_preserves_empty_foreign_directory_after_last_absence_check` — PASS.
- `test_stcvrc_observer_recovery_failures.ObserverRecoveryFailureTest.test_full_apply_preserves_foreign_directory_created_after_last_absence_check` — PASS.

Команда из candidate directory:
`python -B preparation/run_preparation.py --work-dir <scratch> --artifacts-root <external-artifacts-root>`.
Python3.13.13; pinned requirements и exact installer/core hashes
не менялись; binaries только хешировались, не запускались. Без exact binaries
artifact check остаётся SKIP, не PASS. Предыдущие92/105 PASS и их source hashes
сохранены как исторические evidence, не переименованы в результат нового source.

Новые регрессии исполняют actual Apply-Observer и полный внешний production
Apply try/catch/finally. Чужой observer внедряется после последней реальной проверки
отсутствия внутри Apply-Observer. Отдельно покрыт существующий пустой каталог.
Проверяются отсутствие payload copy/claims и воздействия на чужую task, hashes
всех файлов/history, FAIL result/guard и освобождение настоящего file lock.
Независимое внутреннее read-only review production diff и full-entry fixture —
PASS; это дополнительная проверка исходников, не повторный Windows-прогон.

Immutable старые transactions не hotpatch. Нужен новый staging/script hash.
Native Scheduler/SYSTEM interruption/retry, TUN/recovery, VM/reboot/logon/cleanup
и Work-host support остаются отдельными открытыми gates. В этой подготовке не было
network/VM/runtime writes, PR changes, merge/release или Home/Work rollout.

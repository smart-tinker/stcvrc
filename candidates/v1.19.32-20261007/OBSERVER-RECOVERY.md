# Исправление двух observer rollback-сценариев

Дата: 2026-10-15T17:07:27.003274+00:00. Проверен source follow-up к68fd80dc.
**Offline 105 PASS, failures/errors/skips0; 13 новых regression cases.**
VM/runtime recovery НЕ принято; Home/Work-ready NO.

## 1. HTTP/core failure не пропускает observer recovery

В68fd80dc внешняя Check-Http могла прервать Restore-Old до Restore-Observer.
Теперь observer recovery вызывается в finally даже при ошибке HTTP, ожидания core
или проверки его backup. Ошибки core/HTTP и observer учитываются независимо.
При любой незавершённой части итог FAIL/rollback-incomplete, guard не снимается;
успешно восстановленный observer не маскирует ошибку сети.

## 2. Сторонний observer после empty baseline сохраняется

Статический STCVRC_OBSERVER_V1 и совпадение candidate files/arguments не доказывают
владение транзакцией. Теперь fresh root создаётся без Force и получает отдельные
transaction marker/receipt, привязанные к immutable plan hash. Новая task получает
transaction description, identity/schedule/readback проверки и XML hash receipt.
Task регистрируется без Force: появившаяся между проверкой и регистрацией чужая
задача не заменяется. Без собственного claim откат не вызывает даже Stop-Observer;
чужие task/XML/Enabled/files/history сохраняются, итог — conflict/incomplete.
Сбой observer не блокирует попытку вернуть UI/core.

Дополнительно покрыты partial Apply, свой полный Apply→rollback, подмена task,
drift XML при прежних arguments/description и прерывания на границах task receipt.
Durable registration intent записывается до регистрации; только Settings/Enabled
нормализуется при сравнении recovery XML, так что прерывание после Disable не
лишается доказательства владения. Другие настройки/identity по-прежнему проверяются.
История data не откатывается и не удаляется. Неизвестный payload/ownership drift
сохраняется с FAIL; произвольная конкурентная запись администратора не сериализована
нашим transaction lock и не объявляется атомарной OS-гарантией.

## Evidence и воспроизведение

- [Свежий полный runner](preparation/evidence/observer-recovery/preparation-tests.json): 105 PASS.
- [Лог всех cases](preparation/evidence/observer-recovery/preparation-tests.txt).
- [RED исходных failure paths](preparation/evidence/observer-recovery/regression-red.txt):
  на сохранённом source68fd80dc 9 cases, 6 FAIL и3 PASS; это намеренный regression RED,
  не наблюдавшаяся авария на ВМ. Fixture XML затем уточнён до namespaced XML для
  проверки реального recovery-normalizer; исходный RED сохранён.
- [RED двух interruption boundaries](preparation/evidence/observer-recovery/interrupted-red.txt):
  независимое ревью воспроизвело отсутствие created/quiesced receipt после регистрации
  и Disable; оба сценария входят в свежий полный GREEN.
- [Actual scripts/tests и source maps](preparation/provenance.json): 29 maps,
  26 из28 прежних originals не менялись;
  guard и старый fixture adapter исправлены, добавлен regression module.
- Новый модуль исполняет реальные AST Apply-Observer/Restore-Old/Restore-Observer/
  Stop-Observer и file I/O. Task/service/network/ACL effects — явные offline fixtures.
  Python3.13.13, существующие pinned PyYAML6.0.2/psutil6.1.1;
  dependency install не выполнялся. Exact installer/core binaries только хешировались.

Команда из candidate directory:
`python -B preparation/run_preparation.py --work-dir <scratch> --artifacts-root <external-artifacts-root>`.
Без exact binaries artifact check остаётся SKIP, не PASS. Исторические92 PASS и
их source hashes сохранены отдельно, не переименованы в текущий результат.

Immutable старые staged transactions не hotpatch: использовать только новый staging
с новым script hash. TUN/recovery, native Task Scheduler/SYSTEM interruption/retry,
full VM integration/reboot/logon/cleanup и Work-host support остаются открытыми.
PR draft; без merge/release/rollout. VM, Home/Work и runtime в этом исправлении не менялись.

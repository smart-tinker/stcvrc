# P2: Hidden-содержимое при observer cleanup

Дата: 16.10.2026. Статус: локально исправлено и проверено; source-review publication. Независимое повторное P2-review открыто.
База публичного diff: e599d4b2411b76387157eb322a8183da9b93cfa9, PR #2 smart-tinker/stcvrc.

## Вывод и границы

Замечание Оскара подтверждено по коду. Compress-Archive пропускает Hidden-файлы
и каталоги; до исправления общий cleanup guard их допускал. Это риск потери
неархивированных данных, не свидетельство потери реальных пользовательских данных.
Источник: https://learn.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Archive/Compress-Archive?view=powershell-5.1

Минимальный fail-closed fix: Hidden у root или любого вложенного файла/каталога
вызывает `Observer cleanup hidden content`. Общий guard исполняется до архивации
и повторно после скачивания архива непосредственно перед Remove-Item.
Ownership, inactive, reparse, path и size guards не ослаблены. Атрибуты не снимаются.
Это НЕ побайтовая проверка полноты ZIP и НЕ блокировка произвольных конкурентных записей.

## Реальное исполнение

Windows PowerShell 5.1.26100.9549; Python 3.13.13. Только собственные временные
fixture-каталоги в Hermes scratch. Production functions извлекаются через AST;
реальные чтения JSON, Hidden attrs, archive и deletion выполняет PowerShell.
Scheduler/process inventory заменены пустыми fixture-функциями. VM, сеть,
service lifecycle, profiles, TUN/reboot, main и PR metadata не затронуты.

- RED на исходном коде: 6 тестов, 6 FAIL (`RuntimeError not raised`), 0 ERROR/SKIP.
- GREEN после исправления: весь cleanup-модуль 19/19 PASS, 0 FAIL/ERROR/SKIP.
- Новые случаи: Hidden-файл, Hidden-каталог и Hidden-root; каждый до архивации
  и отдельно с установкой Hidden в callback после скачивания ZIP.
- Проверяется настоящий Windows Hidden bit, достигнутый callback, сохранённые
  bytes/директории/атрибуты, существующий root и 0/1 скачиваний соответственно.
- Прежние 13 ownership/marker/claim/history тестов, включая положительный cleanup,
  остались GREEN. Новый полный 145/163-runner и public rerun НЕ выполнялись.

Воспроизведение: `python -B -m unittest discover -s candidates/v1.19.32-20261007/preparation/scripts -p test_stcvrc_atomic_observer_cleanup.py -v`
Адресно только новые случаи: добавить `-k hidden`.
Используется исправный Python; штатный launcher этой сессии был недоступен,
реальный прогон выполнен установленным Python 3.13.13.

## Версии и ревью

`review.patch` меняет ровно два sanitized source-файла, только добавлением
Hidden guard и регрессий. `git apply --check` на неизменённой pinned public-копии
PASS. Original/public hashes до изменения проверены по сохранённой provenance.
Остальные source maps и frozen 145/163 packages не редактировались.
`regression.json` связывает новые исходники, базу, raw и sanitized logs и diff.
Red log обезличен только в локальных traceback-путях. GREEN log не содержал private identity.
Независимый локальный code-review delta: блокирующих замечаний нет; без повторения тестов.

Внешнее ревью Оскара закрывает marker и Move→receipt на уровне исходников;
его 33 hashes, 15 bindings и 145-log checks не являются новым Windows-прогоном.
Для рассмотренной e599d4b2 generation VM runs 034522/041014 остаются FAIL с assisted
recovery. Baseline 8/8 не доказывает автоматический rollback. Native причина
исходного Stop-Service остаётся UNKNOWN. XML-recovery, отдельные 163 PASS/042843
и этот P2 не объединяются с тем ревью. Полная VM-приёмка и Home/Work readiness открыты.

## Публикация и source binding

Эльдар разрешил отдельную публикацию P2 в существующую review-ветку PR #2.
Два changed original/public hashes и сохранённые времена исполнения приведены
в regression.json; все текущие public source maps — в ../../provenance.json.
Локальные 19 PASS не означают выполнения обезличенных public copies.
Public reexecution, full preparation runner и VM: NOT_RUN.
Прежние 145 PASS/source-binding относятся только к immutable e599d4b2;
два old hashes не покрывают новые P2 bytes.
XML-recovery, 163 PASS/042843, main/merge/release, PR metadata/comments,
reviewer requests и runtime в эту публикацию не входят.

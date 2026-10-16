> Текущий source snapshot содержит отдельный [P2 Hidden cleanup](preparation/evidence/cleanup-hidden-p2/README.md). Ниже сохранён отчёт поколения e599d4b2; его 145 PASS не покрывают два новых P2 source bytes. Старая publication NOT_STARTED ниже — исторический pre-publication статус, не текущий head.

# VM-readiness follow-up — версия с 145 PASS, не VM-ready

Base: `5813dcfe958e884858e35da4acd8f2306f2f319c`. Публикация NOT_STARTED.
**Canonical offline 145/145 PASS**, failures/errors/skips 0;
checkedUtc `2026-10-16T01:04:24.277970+00:00`. Public reexecution NOT_RUN.
Это сохранённый прогон, не повторная проверка и не automatic VM PASS.

## Точная граница исходников

В этот snapshot уже входят cleanup собственного marker, embedded claim до
Directory.Move, desktop same-session check, bounded service-stop wait и
compressed command envelope. Их нельзя ошибочно считать изменениями после 145 PASS.

Canonical guard SHA-256:
`106644394117983ab02edbb13269333788d22704ff9ed2b99f2d078fb36d178d`.
Canonical harness SHA-256:
`c2a9740b5d36b29f2a4cbf20c5a94e3572cf3e77020a37e0dc03b8c08bf3f3b2`.
Public bytes обезличены, original/public hashes не тождественны:
[33 source maps](https://github.com/smart-tinker/stcvrc/blob/e599d4b2411b76387157eb322a8183da9b93cfa9/candidates/v1.19.32-20261007/preparation/provenance.json),
[15 report-source bindings](preparation/evidence/vm-readiness-followup/source-binding.json),
[actual report](preparation/evidence/vm-readiness-followup/original-preparation-tests.json),
[sanitized actual log](preparation/evidence/vm-readiness-followup/original-preparation-tests.txt).
Неизменённые источники тоже сверены; executable entry points не запускались.

**Исключён последующий XML-recovery guard** с original SHA-256
`7176b3e3b88f9a4dab50c053e92c15746f4041cef610f6e34b2da33c4a3b17bd`.
Он учитывает schema-default omissions native Scheduler; его нельзя считать
проверенным отчётом 145 PASS или включённым в эти public source bytes.

## Два observer-исправления

- Cleanup допускает только exact markers/claim; data архивируется до удаления,
  ownership повторно проверяется. Foreign payload/markers/drift запрещают удаление.
- Embedded `.stcvrc-claim.json` создаётся до Directory.Move и переносится атомарно
  с root. Missing/corrupt acquisition proof сохраняет fail-closed.
- Сохранённые targeted Move→receipt 6/6 GREEN; в полном логе 13 cleanup cases ok.
  Это offline AST/temp-file fixtures, не power-loss/Scheduler/ACL acceptance.

## VM attempt 20261016-034522: FAIL, частичное изменение

Installer 2.5.8 начался; файл core изменился. Это не pre-mutation отказ.
Сохранённый `apply-error.json` содержит только:
`type=ServiceCommandException`, `line=634`, `at=2026-10-16T00:49:49.0650956Z`.
Строка immutable transaction:

```powershell
if($s -and $s.Status -ne 'Stopped'){Stop-Service -Name $ServiceName -Force;$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}
```

Exception.Message, FullyQualifiedErrorId, InvocationInfo и native error code
**не сохранены — UNKNOWN**. Класс исключения не выдаётся за точный текст ошибки.
Автоматический rollback: coreRestored=false, observerRestored=true,
recoveryError=ServiceCommandException. Причина native exception UNKNOWN.

Штатный исходный Rollback впоследствии выполнен вручную: rolled-back,
UI2.5.5, baseline executing core, files/core/observer restored true.
Outer Restore вернул 7 original paths/ACL и канал. Exact cleanup прочитан обратно:
lab/control/observer absent, runtime tasks/processes пусты; архив 20/20 verified.
Immediate baseline 7/8: только BITS Manual→Auto. Службы не ремонтировали.
Delayed same-principal baseline **8/8 PASS**, readback
`2026-10-16T04:09:16.3422618+03:00`, BITS естественно Manual.

## VM attempt 20261016-041014: отдельный FAIL

Исходный baseline 8/8 подтверждён перед staging. Snapshot guard 10664439…
не hotpatch. UI2.5.8 установлен. Apply: RuntimeException line184, исходный throw
`Observer task Enabled setting unavailable`: native export опустил schema-default
Settings/Enabled. Core восстановлен автоматически, observer нет;
guard остался rollback-incomplete.

После проверки собственных claims/tasks выполнено assisted removal только своей
observer task; исходный Rollback вернул UI2.5.5/core/files/observer. Outer Restore
вернул 7 original paths/ACL/channel; exact cleanup/readback absent;
23/23 control files byte-verified, 2 observer archives verified.
Immediate baseline снова 7/8: BITS Manual→Auto. BITS не меняли.
Delayed same-principal baseline **8/8 PASS**, readback
`2026-10-16T04:28:05.7604462+03:00`, BITS естественно Manual.

В обоих случаях исходные FAIL отчёты сохранены неизменными.
**Восстановление baseline подтверждено; automatic VM acceptance не подтверждена.**
Подробные безопасные поля и hashes локальных первичных result-файлов:
[source binding](preparation/evidence/vm-readiness-followup/source-binding.json).
Raw archives, private profiles/accesses, host-bound originals и binaries исключены.
Home/Work-ready NO; TUN/reboot/interruption/Work-generation gates открыты.

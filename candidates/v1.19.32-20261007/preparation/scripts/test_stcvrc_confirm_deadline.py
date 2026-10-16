"""Execute the real Confirm branch with a deterministic health-check clock.

Only AST-selected transaction control flow and its real file lock run here.
System/service/network operations are replaced by local in-memory fixtures.
This does not execute a rollout or establish Windows integration readiness.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("stcvrc-safe-rollout.ps1")


@unittest.skipUnless(os.name == "nt", "Windows PowerShell transaction branch")
class ConfirmDeadlineTest(unittest.TestCase):
    def run_confirm(self, *, health_seconds=18, initial_seconds=16,
                    health_action="none", consumer_confirmed=True,
                    watch_after=False):
        with tempfile.TemporaryDirectory(prefix="stcvrc-confirm-", dir=os.environ.get("TMPDIR")) as tmp:
            code = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Production source parse failure'}
foreach($name in @('Acquire-Lock','Release-Lock')){
    $f=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true)
    if($f){. ([ScriptBlock]::Create($f.Extent.Text))}
}
$confirm=$null;$watch=$null
foreach($statement in $ast.FindAll({param($n) $n -is [Management.Automation.Language.IfStatementAst]},$true)){
    foreach($clause in $statement.Clauses){
        if($clause.Item1.Extent.Text -ceq '$Mode -eq ''Confirm'''){$confirm=$clause.Item2}
        if($clause.Item1.Extent.Text -ceq '$Mode -eq ''Watch'''){$watch=$clause.Item2}
    }
}
if(-not $confirm){throw 'Real Confirm branch not found'}
$body=$confirm.Extent.Text
$body=$body.Substring(1,$body.Length-2)
if(-not $watch){throw 'Real Watch branch not found'}
$watchBody=$watch.Extent.Text
$watchBody=$watchBody.Substring(1,$watchBody.Length-2)
$Root='__ROOT__';$PlanPath=Join-Path $Root 'plan.json';$StatePath=Join-Path $Root 'state.json'
$ConsumerConfirmed=__CONSUMER_CONFIRMED__;$Mode='Confirm';$Lock=$null
$script:clock=[DateTime]::UtcNow
$script:armed=@{deadline=$script:clock.AddSeconds(__INITIAL_SECONDS__).ToString('o');planHash='plan-fixture';boot='boot-fixture'}
$script:fixtureArmedHash='armed-fixture';$script:fixturePlanHash='plan-fixture'
$script:phase='awaiting-confirmation';$script:guardActive=$true;$script:healthCalls=0
$script:healthLockWasAvailable=$false
$script:watchStops=0;$script:watchRestores=0
function Get-Date {$script:clock}
function Read-Json([string]$Path){
    if([IO.Path]::GetFileName($Path) -ceq 'armed.json'){return $script:armed}
    if([IO.Path]::GetFileName($Path) -ceq 'state.json'){return @{phase=$script:phase}}
    throw 'Unexpected fixture read'
}
function Hash([string]$Path){
    if([IO.Path]::GetFileName($Path) -ceq 'armed.json'){return $script:fixtureArmedHash}
    if($Path -ceq $PlanPath){return $script:fixturePlanHash}
    throw 'Unexpected fixture hash'
}
function State([string]$Phase){$script:phase=$Phase}
function Remove-GuardTask {$script:guardActive=$false}
function Write-Json([string]$Path,$Value){}
function Get-Process([int]$Id){@{SessionId=0}}
function Get-CimInstance($ClassName){
    if($ClassName -cne 'Win32_OperatingSystem'){throw 'Unexpected fixture system operation'}
    @{LastBootUpTime=[DateTime]::Parse('2000-01-01T00:00:00Z').ToUniversalTime()}
}
function Stop-ApplyWorker {$script:watchStops++}
function Restore-Old {$script:watchRestores++;State 'rolled-back';Remove-GuardTask}
function Invoke-WatchFixture {
    # The actual Watch block is triggered by a fixture boot change, not a
    # modified clock expression or a Python reimplementation of its logic.
    if(-not $script:healthLockWasAvailable){throw 'Confirm still holds its lock during health check'}
    try {. ([ScriptBlock]::Create($watchBody))}
    finally {if($Lock){$Lock.Dispose();$script:Lock=$null}}
}
function Candidate-Check {
    $probe=$null
    try {
        $probe=[IO.File]::Open((Join-Path $Root 'transaction.lock'),'OpenOrCreate','ReadWrite','None')
        $script:healthLockWasAvailable=$true
    } catch [IO.IOException] {} finally {if($probe){$probe.Dispose()}}
    # Default: two passing 9-second operations from the review scenario.
    # Every alternative advances monotonically too; there is no real wait.
    foreach($step in @((__HEALTH_SECONDS__/2.0),(__HEALTH_SECONDS__/2.0))){
        $script:clock=$script:clock.AddSeconds($step)
        $script:healthCalls++
    }
    switch('__HEALTH_ACTION__'){
        'watch' {Invoke-WatchFixture}
        'armed-drift' {$script:fixtureArmedHash='different-armed-generation'}
        'plan-drift' {$script:fixturePlanHash='different-plan'}
        'failure' {throw 'Fixture health check failure'}
    }
    @{pass=$true}
}
$rejected=$false;$reason=$null
try {. ([ScriptBlock]::Create($body))}catch{$rejected=$true;$reason=$_.Exception.Message}
finally {if($Lock){$Lock.Dispose();$Lock=$null}}
$phaseAfterConfirm=$script:phase;$guardAfterConfirm=$script:guardActive
if(__WATCH_AFTER__){Invoke-WatchFixture}
@{rejected=$rejected;reason=$reason;phase=$script:phase;guardActive=$script:guardActive;
  phaseAfterConfirm=$phaseAfterConfirm;guardAfterConfirm=$guardAfterConfirm;
  healthCalls=$script:healthCalls;healthLockWasAvailable=$script:healthLockWasAvailable;
  watchStops=$script:watchStops;watchRestores=$script:watchRestores;
  now=$script:clock.ToString('o');deadline=$script:armed.deadline}|ConvertTo-Json -Compress
""".replace("__SOURCE__", str(SCRIPT).replace("'", "''")).replace(
                "__ROOT__", str(Path(tmp)).replace("'", "''")
            ).replace("__HEALTH_SECONDS__", str(health_seconds)).replace(
                "__INITIAL_SECONDS__", str(initial_seconds)
            ).replace("__HEALTH_ACTION__", health_action).replace(
                "__CONSUMER_CONFIRMED__", "$true" if consumer_confirmed else "$false"
            ).replace("__WATCH_AFTER__", "$true" if watch_after else "$false")
            shell = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            result = subprocess.run(
                [str(shell), "-NoProfile", "-NonInteractive", "-EncodedCommand",
                 base64.b64encode(code.encode("utf-16le")).decode()],
                capture_output=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            report = json.loads(result.stdout.decode("utf-8-sig"))
            # Keep executable observations in both RED and GREEN runner logs.
            print("CONFIRM_DEADLINE_OBSERVATION " + json.dumps(report, sort_keys=True), flush=True)
            return report

    def test_health_check_crossing_deadline_cannot_commit_or_remove_guard(self):
        report = self.run_confirm()
        self.assertEqual(report["healthCalls"], 2, report)
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["phase"], "awaiting-confirmation", report)
        self.assertTrue(report["guardActive"], report)

    def test_late_rejection_keeps_actual_watch_recovery_available(self):
        report = self.run_confirm(watch_after=True)
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["phaseAfterConfirm"], "awaiting-confirmation", report)
        self.assertTrue(report["guardAfterConfirm"], report)
        self.assertEqual(report["watchStops"], 1, report)
        self.assertEqual(report["watchRestores"], 1, report)
        self.assertEqual(report["phase"], "rolled-back", report)
        self.assertFalse(report["guardActive"], report)

    def test_healthy_confirm_with_enough_time_commits(self):
        report = self.run_confirm(initial_seconds=60)
        self.assertFalse(report["rejected"], report)
        self.assertEqual(report["phase"], "committed", report)
        self.assertFalse(report["guardActive"], report)
        self.assertTrue(report["healthLockWasAvailable"], report)

    def test_immediate_health_with_sixteen_seconds_left_can_commit(self):
        report = self.run_confirm(health_seconds=0)
        self.assertFalse(report["rejected"], report)
        self.assertEqual(report["phase"], "committed", report)
        self.assertFalse(report["guardActive"], report)

    def test_one_second_health_reaching_exact_reserve_cannot_commit(self):
        report = self.run_confirm(health_seconds=1)
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["phase"], "awaiting-confirmation", report)
        self.assertTrue(report["guardActive"], report)

    def test_final_fifteen_second_reserve_is_exclusive(self):
        for remaining, rejection in ((14, True), (15, True), (16, False)):
            with self.subTest(final_seconds_remaining=remaining):
                report = self.run_confirm(initial_seconds=33, health_seconds=33-remaining)
                self.assertEqual(report["rejected"], rejection, report)
                self.assertEqual(report["phase"],
                                 "awaiting-confirmation" if rejection else "committed", report)
                self.assertEqual(report["guardActive"], rejection, report)

    def test_initial_deadline_reserve_rejects_without_health(self):
        report = self.run_confirm(initial_seconds=15)
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["healthCalls"], 0, report)
        self.assertEqual(report["phase"], "awaiting-confirmation", report)
        self.assertTrue(report["guardActive"], report)

    def test_consumer_confirmation_remains_required(self):
        report = self.run_confirm(initial_seconds=60, consumer_confirmed=False)
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["healthCalls"], 0, report)
        self.assertEqual(report["phase"], "awaiting-confirmation", report)
        self.assertTrue(report["guardActive"], report)

    def test_watch_rollback_during_health_cannot_be_overwritten_by_confirm(self):
        report = self.run_confirm(initial_seconds=60, health_action="watch")
        self.assertTrue(report["rejected"], report)
        self.assertTrue(report["healthLockWasAvailable"], report)
        self.assertEqual(report["watchRestores"], 1, report)
        self.assertEqual(report["phase"], "rolled-back", report)
        self.assertFalse(report["guardActive"], report)

    def test_rearmed_or_changed_plan_during_health_cannot_commit(self):
        for action in ("armed-drift", "plan-drift"):
            with self.subTest(drift=action):
                report = self.run_confirm(initial_seconds=60, health_action=action)
                self.assertTrue(report["rejected"], report)
                self.assertEqual(report["phase"], "awaiting-confirmation", report)
                self.assertTrue(report["guardActive"], report)

    def test_health_failure_keeps_guard(self):
        report = self.run_confirm(initial_seconds=60, health_action="failure")
        self.assertTrue(report["rejected"], report)
        self.assertEqual(report["phase"], "awaiting-confirmation", report)
        self.assertTrue(report["guardActive"], report)


if __name__ == "__main__":
    unittest.main()

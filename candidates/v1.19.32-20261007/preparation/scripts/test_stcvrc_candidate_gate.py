"""Offline transaction-boundary checks; never connects to a host."""
import ast
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import stmc_yaml
from stcvrc_lab_stack import STACKS

ROOT=Path(__file__).resolve().parents[1]

class PreparationReached(Exception):
    pass

class CandidateTransactionTests(unittest.TestCase):
    def prepare(self, source):
        module=ast.parse((ROOT/'scripts/invoke-uservm-stcvrc-desktop-autostart.py').read_text(encoding='utf-8'))
        function=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='core_rollout_gate')
        code=compile(ast.Module(body=[function],type_ignores=[]),'transaction-input-boundary','exec')
        calls=[]
        downloads=[]
        def download(remote,local):
            downloads.append(remote)
            value={'items':[{'uid':'gate','file':'LSTCVRCGate.yaml'}],'current':'gate'} if local.name=='profiles.yaml' else {}
            local.write_bytes(stmc_yaml.dump(value))
        def command(argv,timeout):
            calls.append(argv)
            raise PreparationReached()
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT/'local/labs',prefix='candidate-input-test-') as directory:
            scope={'local':Path(directory),'app':r'C:\Users\FixtureUser\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev',
                   'lab':r'C:\Users\FixtureUser\stcvrc-fullstack-lab','stamp':'20261015-120000','PROJECT':ROOT,
                   'STACKS':STACKS,'sys':__import__('sys'),'hashlib':hashlib,'stmc_yaml':stmc_yaml,'json':__import__('json'),
                   'download':download,'H':{'command':command},
                   'args':SimpleNamespace(stack=source,ui_rollout_target_stack='candidate',observer_config_gate=False,atomic_observer_bundle=None),
                   'report':{'setup':{'groups':[{'name':'FOREIGN-EGRESS','now':'GC','type':'Selector'}]}}}
            exec(code,scope)
            with self.assertRaises(PreparationReached):scope['core_rollout_gate'](ui_update=True)
        return calls[0],downloads

    def test_home_rollback_uses_current_approved_owner_runtime_and_exact_pair(self):
        argv,downloads=self.prepare('next')
        self.assertEqual(argv[argv.index('--old-core')+1],str(ROOT/STACKS['next']['core']))
        self.assertEqual(argv[argv.index('--candidate-core')+1],str(ROOT/STACKS['candidate']['core']))
        self.assertEqual(argv[argv.index('--source-stack')+1],'next')
        self.assertEqual(argv[argv.index('--target-stack')+1],'candidate')
        self.assertIn('--runtime-config',argv)
        self.assertTrue(any(p.endswith(r'\runtime\config.yaml') for p in downloads))

    def test_work_rollback_preserves_legacy_source_and_exact_target(self):
        argv,downloads=self.prepare('accepted')
        self.assertEqual(argv[argv.index('--old-core')+1],str(ROOT/STACKS['accepted']['core']))
        self.assertEqual(argv[argv.index('--candidate-core')+1],str(ROOT/STACKS['candidate']['core']))
        self.assertEqual(argv[argv.index('--source-stack')+1],'accepted')
        self.assertNotIn('--runtime-config',argv)
        self.assertTrue(any(p.endswith(r'\clash-verge.yaml') for p in downloads))

    def test_observer_installer_accepts_only_reviewed_owner_versions(self):
        import base64, json, os, subprocess
        source=ROOT/'scripts/install-stcvrc-observer-lab.ps1'
        code=r"""
$ErrorActionPreference='Stop'
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('SOURCE',[ref]$t,[ref]$e)
if($e){throw 'Parse failure'}
$node=$ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if(($version.Split')},$true)
if(@($node).Count -ne 1){throw 'Version guard missing'}
$guard=[ScriptBlock]::Create($node[0].Extent.Text)
foreach($version in @('2.5.5','2.5.7','2.5.8','2.5.8.0')){& $guard}
$rejected=0
foreach($version in @('2.5.6','2.5.9','3.0.0','invalid')){
 try{& $guard}catch{$rejected++}
}
@{rejected=$rejected}|ConvertTo-Json -Compress
""".replace('SOURCE',str(source).replace("'","''"))
        shell=Path(os.environ['WINDIR'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        result=subprocess.run([str(shell),'-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(code.encode('utf-16le')).decode()],capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(json.loads(result.stdout.decode('utf-8-sig'))['rejected'],4)

    def test_invalid_cli_pairs_and_mixed_gates_fail_before_remote_setup(self):
        # Compile only argument validation, not the runtime/SSH entrypoint.
        from test_stcvrc_tun_gate import harness_arguments
        prefix=['--preserve-service-state']
        cases=(['--ui-rollout-gate','--stack','candidate'],
               ['--ui-rollout-gate','--stack','next','--ui-rollout-target-stack','candidate','--reboot'],
               ['--stack','accepted','--ui-rollout-target-stack','candidate'],
               ['--stack','accepted','--ui-rollout-gate','--ui-rollout-target-stack','next','--tun-gate'])
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaises(SystemExit) as result:
                    harness_arguments(prefix+args)
                self.assertEqual(result.exception.code,2)

    def test_post_rollback_readback_accepts_only_actual_source_core(self):
        text=(ROOT/'scripts/invoke-uservm-stcvrc-desktop-autostart.py').read_text(encoding='utf-8')
        module=ast.parse(text)
        node=next(n for n in ast.walk(module) if isinstance(n,ast.AugAssign) and 'uiRollbackReadback' in ast.get_source_segment(text,n))
        expression=compile(ast.Expression(body=node.value),'rollback-readback','eval')
        for source in ('accepted','next'):
            with self.subTest(source=source):
                report={'uiRollout':{'pass':True},'uiRollbackReadback':{'coreHash':STACKS[source]['coreSha256']}}
                scope={'report':report,'stack':STACKS[source],'STACKS':STACKS}
                self.assertTrue(eval(expression,scope))
                report['uiRollbackReadback']['coreHash']=STACKS['candidate']['coreSha256']
                self.assertFalse(eval(expression,scope))

    def test_candidate_pins_exact_258_artifacts(self):
        import hashlib
        import os
        candidate=STACKS['candidate']
        artifact_root=Path(os.environ.get('STCVRC_PREPARATION_ARTIFACTS_ROOT',ROOT))
        if 'STCVRC_PREPARATION_ARTIFACTS_ROOT' not in os.environ and not all((artifact_root/candidate[k]).is_file() for k in ('installer','core')):
            self.skipTest('Exact candidate binaries required: pass --artifacts-root to run_preparation.py')
        self.assertEqual(candidate['uiVersion'],'2.5.8')
        for file_key,hash_key in (('installer','installerSha256'),('core','coreSha256')):
            self.assertEqual(hashlib.sha256((artifact_root/candidate[file_key]).read_bytes()).hexdigest(),candidate[hash_key])

if __name__=='__main__':unittest.main()

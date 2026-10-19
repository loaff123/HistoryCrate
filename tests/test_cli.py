import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout,redirect_stderr
from unittest.mock import patch

class CliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.cli'),'CLI foundation is not implemented')
        from historycrate.cli import main
        self.main=main
    def invoke(self,args):
        out=io.StringIO();err=io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=self.main(args)
        return code,out.getvalue(),err.getvalue()
    def test_unimplemented_commands_never_succeed(self):
        for command in ('inspect','pack','verify','restore','explain'):
            code,out,err=self.invoke([command])
            self.assertNotEqual(code,0)
            self.assertEqual(json.loads(out)['status'],'blocked')
            self.assertEqual(json.loads(out)['publication'],'not-published')
    def test_invalid_invocation_machine_report(self):
        code,out,err=self.invoke(['doctor'])
        self.assertEqual(code,2);self.assertEqual(json.loads(out)['diagnostics'][0]['code'],'INVALID_INVOCATION')
    def test_doctor_propagates_observation_failure(self):
        from historycrate.errors import CrateError
        with patch('historycrate.cli.doctor',side_effect=CrateError('OBSERVATION_UNREADABLE',5,{'resource':'procfs'})):
            code,out,err=self.invoke(['doctor','--git','/usr/local/bin/git','--git-lfs','/tmp/git-lfs'])
        self.assertEqual(code,5)
        self.assertEqual(json.loads(out)['status'],'blocked')
        self.assertEqual(json.loads(out)['diagnostics'][0]['code'],'OBSERVATION_UNREADABLE')
    def test_help_discloses_profile(self):
        code,out,err=self.invoke(['--help'])
        self.assertEqual(code,0);self.assertIn('No OS sandbox',out)
    def test_cancel_returns_130(self):
        with patch('historycrate.cli.doctor',side_effect=KeyboardInterrupt):
            code,out,err=self.invoke(['doctor','--git','/usr/local/bin/git','--git-lfs','/tmp/git-lfs'])
        self.assertEqual(code,130)
        self.assertEqual(json.loads(out)['status'],'blocked')

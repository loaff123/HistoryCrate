from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS, GIT_EXEC as TEST_GIT_EXEC
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import _ObjectFrame, Job, Toolchain

class NativeUnitTests(unittest.TestCase):
    def test_object_frame_accepts_memoryview_chunks(self):
        oid='a'*40;sink=io.BytesIO();frame=_ObjectFrame(sink,oid,3)
        frame.write(memoryview(f'{oid} blob 3\n'.encode()+b'abc\n'))
        frame.finish();self.assertEqual(sink.getvalue(),b'abc')
        self.assertEqual(frame.framing_overhead,202)
    def test_object_frame_rejects_overlong_header_even_with_newline(self):
        frame=_ObjectFrame(io.BytesIO(),'a'*40,3)
        with self.assertRaises(CrateError):frame.write(b'a'*201+b'\n')
    def test_object_frame_rejects_missing_trailer_and_extra_bytes(self):
        for suffix in (b'',b'\nx'):
            frame=_ObjectFrame(io.BytesIO(),'a'*40,3)
            with self.assertRaises(CrateError):
                frame.write(b'a'*40+b' blob 3\nabc'+suffix);frame.finish()
    def test_job_preserves_uncertain_scratch_and_closes_private_handle(self):
        dummy=Toolchain(TEST_GIT,Path('/tmp/nonexistent/git-lfs'),TEST_GIT_EXEC,'2.52.0','3.8.0',{}, {})
        with tempfile.TemporaryDirectory() as d:
            with patch('historycrate.native.NativeAdapter'):
                job=Job(Limits(),dummy,output_parent=Path(d));job.__enter__()
                root=job.root;(root/'sentinel').write_text('keep')
                error=CrateError('CLEANUP_UNCERTAIN',5,{'observations':{'cleanup':{'uncertain':True}}})
                job.__exit__(CrateError,error,None)
                self.assertTrue(root.exists());self.assertEqual((root/'sentinel').read_text(),'keep')
    def test_job_uses_inode_pinned_lifecycle(self):
        dummy=Toolchain(TEST_GIT,Path('/tmp/nonexistent/git-lfs'),TEST_GIT_EXEC,'2.52.0','3.8.0',{}, {})
        with tempfile.TemporaryDirectory() as d:
            with patch('historycrate.native.NativeAdapter'):
                job=Job(Limits(),dummy,output_parent=Path(d));job.__enter__()
                moved=Path(d)/'moved';job.root.rename(moved);job.root.mkdir()
                (job.root/'replacement').write_text('keep')
                with self.assertRaises(CrateError):job.__exit__(None,None,None)
                self.assertEqual((job.root/'replacement').read_text(),'keep')

    def test_owned_source_disjoint_from_system_owned_tool_is_accepted(self):
        dummy=Toolchain(TEST_GIT,TEST_LFS,TEST_GIT_EXEC,'2.52.0','3.8.0',{}, {})
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'source';source.mkdir(mode=0o700)
            with patch('historycrate.native.NativeAdapter'):
                with Job(Limits(),dummy,source_paths=(source,)) as job:
                    self.assertTrue(job.root.is_dir())

    def test_native_paths_reject_unicode_controls_and_apply_lowered_limits(self):
        from historycrate.native import _path
        for path in ('x\u0085y','x\u009by','\ud800'):
            with self.subTest(path=repr(path)),self.assertRaises(CrateError):_path(path)
        with self.assertRaises(CrateError):_path('long',Limits().lower({'path_bytes':3}))
        with self.assertRaises(CrateError):_path('aa/bb',Limits().lower({'component_bytes':1}))
        with self.assertRaises(CrateError):_path('a/b',Limits().lower({'path_depth':1}))

    def test_job_rejects_source_overlap_before_creating_scratch(self):
        dummy=Toolchain(TEST_GIT,TEST_LFS,TEST_GIT_EXEC,'2.52.0','3.8.0',{}, {})
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'work' / '.git';source.mkdir(mode=0o700,parents=True)
            for parent in (source,source.parent):
                before=set(parent.iterdir())
                with self.assertRaises(CrateError):
                    with Job(Limits(),dummy,output_parent=parent,source_paths=(source,)):pass
                self.assertEqual(set(parent.iterdir()),before)

    def test_job_default_scratch_refuses_source_but_allows_shared_ancestor(self):
        dummy=Toolchain(TEST_GIT,TEST_LFS,TEST_GIT_EXEC,'2.52.0','3.8.0',{}, {})
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);source=parent/'work'/'.git';source.mkdir(mode=0o700,parents=True)
            with patch('tempfile.gettempdir',return_value=str(source.parent)),self.assertRaises(CrateError):
                with Job(Limits(),dummy,source_paths=(source,)):pass
            with patch('historycrate.native.NativeAdapter'):
                with Job(Limits(),dummy,output_parent=parent,source_paths=(source,)) as job:
                    self.assertEqual(job.root.parent,parent)

    def test_doctor_resource_probes_are_actual_bounded_checks(self):
        from historycrate import qualification
        self.assertTrue(hasattr(qualification,'qualify_safeguards'),'doctor resource probes missing')
        with tempfile.TemporaryDirectory() as d:
            report=qualification.qualify_safeguards(Path(d),Limits())
        self.assertEqual(set(report),{'observer_rss_abort','capture_abort','timeout_reaped'})
        for name,entry in report.items():
            self.assertTrue(entry['expected_failure_observed'],name)
            self.assertTrue(entry['observations']['cleanup']['direct_child_reaped'])

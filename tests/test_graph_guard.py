import unittest
from historycrate import closure
from historycrate.errors import CrateError

class IncrementalGraphGuardTests(unittest.TestCase):
    def test_incremental_shared_depth_and_cycle(self):
        self.assertTrue(hasattr(closure,'_GraphGuard'),'incremental graph guard is not implemented')
        checks=[];guard=closure._GraphGuard(2,lambda:checks.append(1))
        guard.add(('a','1'),('b','2'));guard.add(('a','1'),('shared','3'))
        guard.add(('shared','3'),('b','2'));guard.add(('a','1'),('b','2'))
        self.assertEqual(guard.depths[('b','2')],2)
        with self.assertRaises(CrateError) as ctx:guard.add(('b','2'),('c','4'))
        self.assertEqual(ctx.exception.context['resource'],'repository_depth')
        guard=closure._GraphGuard(16,lambda:None);guard.add(('a','1'),('b','2'))
        with self.assertRaises(CrateError) as ctx:guard.add(('b','2'),('a','1'))
        self.assertEqual(ctx.exception.code,'RECURSIVE_GITLINK_CYCLE');self.assertTrue(checks)

    def test_large_loop_observes_controller_checkpoint(self):
        self.assertTrue(hasattr(closure,'_GraphGuard'),'incremental graph guard is not implemented')
        def expired():raise CrateError('BUDGET_EXCEEDED',5,{'resource':'job_wall_seconds'})
        guard=closure._GraphGuard(16,expired)
        with self.assertRaises(CrateError) as ctx:guard.add(('a','1'),('b','2'))
        self.assertEqual(ctx.exception.context['resource'],'job_wall_seconds')

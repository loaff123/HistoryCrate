import unittest
from types import MappingProxyType
from historycrate import model


class StageModelTests(unittest.TestCase):
    def test_graph_records_exist_and_closure_maps_are_frozen_copies(self):
        for name in ('ObjectRecord','CommitRecord','TreeEntry','GitlinkRecord','LfsOccurrence','PayloadRecord','AcquiredRepo','PayloadSet','Closure'):
            self.assertTrue(hasattr(model,name), f'{name} is not implemented')
        roots={'release':('a'*40,)}; seeds={'main':('a'*40,)}
        closure=model.Closure((),roots,seeds,(),(),(),())
        roots.clear(); seeds.clear()
        self.assertEqual(closure.root_ancestors['release'],('a'*40,))
        self.assertEqual(closure.seeds['main'],('a'*40,))
        with self.assertRaises(TypeError): closure.seeds['main']=()

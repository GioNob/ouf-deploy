"""Kernel access-mode semantics and bounded no-follow view paths.

Full namespace/bind behavior is separately qualified with native Docker29.
"""
import os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_selected_runtime
from tools.m2_discovery_installation_profile import current_retained_views as m


class Views(unittest.TestCase):
    def test_per_mount_readonly_is_distinct_from_readwrite_superblock(self):
        raw=b'12 1 0:3 /token /run/token ro,nosuid - tmpfs tmpfs rw,size=32k\n'
        rows=m.parse_mountinfo(raw)
        self.assertTrue(m.select_mount(rows,'/run/token',True)['readOnly'])
        with self.assertRaises(ValueError):m.select_mount(rows,'/run/token',False)
        raw=b'12 1 0:3 /token /run/token rw,nosuid - tmpfs tmpfs ro,size=32k\n'
        with self.assertRaises(ValueError):m.select_mount(m.parse_mountinfo(raw),'/run/token',True)

    def test_exact_mount_no_shadowing_missing_ambiguous_and_prefix_sibling(self):
        row=lambda mid,path:f'{mid} 1 0:3 / {path} ro - tmpfs tmpfs rw\n'.encode()
        for suffix in (row(13,'/run/token/file'),row(13,'/run/token')):
            with self.assertRaises(ValueError):m.select_mount(m.parse_mountinfo(row(12,'/run/token')+suffix),'/run/token',True)
        rows=m.parse_mountinfo(row(12,'/run/token')+row(13,'/run/token-other'))
        self.assertEqual(m.select_mount(rows,'/run/token',True)['mountId'],12)
        with self.assertRaises(ValueError):m.select_mount(rows,'/absent',True)

    def test_complete_mountinfo_optional_fields_escapes_and_bounds(self):
        raw=b'12 1 0:3 / /run/a\\040b ro shared:3 master:1 - tmpfs tmpfs rw\n'
        self.assertEqual(m.parse_mountinfo(raw)[0]['mountPoint'],'/run/a b')
        for bad in (raw.rstrip(b'\n'),raw+raw,raw.replace(b'ro shared',b'ro,rw shared'),
            raw.replace(b'\\040',b'\\999'),raw.replace(b' - ',b' '),raw+b'\x00\n'):
            with self.subTest(bad=bad),self.assertRaises(ValueError):m.parse_mountinfo(bad)
        with patch.dict(m.LIMITS,maximumMountinfoBytes=1),self.assertRaises(ValueError):m.parse_mountinfo(raw)

    def test_view_lookup_opath_only_no_symlink_or_escape(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path=Path(directory);(path/'data').write_bytes(b'NEVER_READ');(path/'link').symlink_to('data')
            root=os.open(path,os.O_PATH|os.O_DIRECTORY);original=os.open;opened=[]
            def no_contents(p,flags,*a,**kw):
                self.assertTrue(flags&os.O_PATH);opened.append(p);return original(p,flags,*a,**kw)
            try:
                with patch.object(os,'open',side_effect=no_contents):
                    fd=m.view_node(root,'/data')
                    try:self.assertEqual(os.fstat(fd).st_ino,(path/'data').stat().st_ino)
                    finally:os.close(fd)
                    with self.assertRaises(ValueError):m.view_node(root,'/link')
                for target in ('../data','/../data','/data/../data','/','//data','/data/'):
                    with self.subTest(target=target),self.assertRaises(ValueError):m.view_node(root,target)
            finally:os.close(root)

    def test_no_foreign_owner_or_public_input_and_callback_override(self):
        with self.assertRaises(ValueError):m.CurrentRetainedMountViews(object())
        with self.assertRaises(TypeError):m.CurrentRetainedMountViews(object(),proc_root='/other')


if __name__=='__main__':unittest.main()

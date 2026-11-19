"""Actual Docker29 mount namespaces; mutations only in disposable CI fixtures.

Production observer has no mount/setns/Engine operation. A CI-only native helper
changes effective flags and shadow mounts while Docker declarations stay fixed.
"""
import copy,json,os,shutil,sqlite3,subprocess,sys,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tests/fixtures')]
import qualify_m2_retained_static_intake_native as fixture
from retained_lifecycle_layout import rotate
from tools.m2_discovery_installation_profile import current_retained_views as m
from tools.m2_discovery_installation_profile import retained_view_capture as capture
from tools.m2_discovery_installation_profile import retained_static_custody as static_prep

HELPER=r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc,char **argv){
  if(argc!=5)return 2;
  char target[PATH_MAX];if(strlen(argv[3])>=sizeof(target))return 2;strcpy(target,argv[3]);
  char *leaf=strrchr(target,'/');if(!leaf||!leaf[1])return 2;*leaf++=0;
  int parent=open(target,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(parent<0){perror("target-parent");return 3;}
  int tree=-1;
  if(!strcmp(argv[2],"bind")){
    tree=syscall(SYS_open_tree,AT_FDCWD,argv[4],OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
    if(tree<0){perror("clone-fixture-bind");return 3;}
  }
  int fd=open(argv[1],O_RDONLY|O_CLOEXEC);
  if(fd<0||setns(fd,CLONE_NEWNS)||fchdir(parent)){perror("namespace-cwd");return 3;}close(fd);close(parent);
  int rc;
  if(!strcmp(argv[2],"rw"))rc=mount(NULL,leaf,NULL,MS_REMOUNT|MS_BIND,NULL);
  else if(!strcmp(argv[2],"ro"))rc=mount(NULL,leaf,NULL,MS_REMOUNT|MS_BIND|MS_RDONLY,NULL);
  else if(!strcmp(argv[2],"bind"))rc=syscall(SYS_move_mount,tree,"",AT_FDCWD,leaf,MOVE_MOUNT_F_EMPTY_PATH);
  else if(!strcmp(argv[2],"unmount"))rc=umount(leaf);
  else return 4;
  if(tree>=0)close(tree);
  if(rc){perror("fixture-mount");return 5;}return 0;
}
'''


class NativeViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.NativeStaticIntake.setUpClass.__func__(cls)
        static_owner=cls.static_observer
        selected={**static_owner.case,'staticCandidatePath':str(static_owner.path),
            'staticCandidateHash':static_owner.bindings['candidateHash'],'staticResultHash':static_owner.bindings['resultHash']}
        for name,value in {'CASE':selected,'ROSTER':static_prep.ROSTER}.items():
            context=patch.object(capture,name,value);context.start();cls.addClassCleanup(context.stop)
        captured=capture.ViewCapture(cls.root/'captured-kernel-views');receipt=capture.collect(captured);captured.put('result.json',receipt)
        record=json.loads((captured.scope/'effective-views.private.json').read_bytes())
        for name,value in {'VIEW_CASE':selected,'VIEW_CANDIDATE':captured.scope/'effective-views.private.json',
            'VIEW_CANDIDATE_HASH':m.digest(record),'VIEW_RESULT_HASH':m.digest(receipt)}.items():
            context=patch.object(m,name,value);context.start();cls.addClassCleanup(context.stop)
        cls.views=m.CurrentRetainedMountViews(cls.static_observer)
        source=cls.root/'view-helper.c';source.write_text(HELPER);cls.helper=cls.root/'view-helper'
        subprocess.run([shutil.which('cc'),'-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(cls.helper)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=True)
        cls.gateway=cls.candidate['peers']['gateway-owner'];cls.pid=cls.gateway['processPin']['pid']
        cls.initial_docker=json.loads(cls.command('inspect',cls.gateway['containerId']))[0]

    def mutate(self,operation,target,source='unused'):
        result=subprocess.run([str(self.helper),'/proc/'+str(self.pid)+'/ns/mnt',operation,
            '/proc/'+str(self.pid)+'/root'+target,str(source)],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr.decode()[:512])

    def unchanged_declaration(self):
        actual=json.loads(self.command('inspect',self.gateway['containerId']))[0]
        for key in ('Id','Image','Config','HostConfig','Mounts'):self.assertEqual(actual[key],self.initial_docker[key])

    def test_a_actual_all_mount_views_use_the_same_static_source_inode_and_effective_flags(self):
        first=self.views.observe()
        for path in self.auth.values():rotate(path)
        db=sqlite3.connect(self.database);self.addCleanup(db.close);db.execute('update fixture set value=value+1');db.commit()
        second=self.views.observe();self.assertEqual(first,second)
        self.assertTrue(second['currentMountDeclarationsMatchEffectiveViews'])
        self.assertEqual((second['readonlyMounts'],second['writableMounts'],second['retainedProcessCount']),(25,4,10))
        self.assertEqual(second['directEngineGets'],0);self.assertEqual(second['mountedFileContentBytesRead'],0)
        self.assertFalse(second['liveOwnerAuthenticated']);self.assertFalse(second['liveDirectoryMembershipObserved']);self.assertFalse(second['completePrivateCustodyProven'])
        self.assertFalse(second['expectedPermissionOrContentPolicyEstablished']);self.assertFalse(second['targetApplyAuthorized'])

    def test_b_actual_readonly_flag_drift_is_detected_even_when_docker_declaration_is_unchanged(self):
        target='/run/ouf-gateway-auth';self.mutate('rw',target)
        try:
            self.unchanged_declaration()
            with self.assertRaisesRegex(ValueError,'EFFECTIVE_MOUNT_ACCESS'):self.views.observe()
        finally:self.mutate('ro',target)

    def test_c_actual_nested_shadow_mount_is_rejected_without_opening_token_content(self):
        target='/run/ouf-gateway-auth/token';source=self.keys['gateway-key'];self.mutate('bind',target,source)
        try:
            self.unchanged_declaration()
            with self.assertRaisesRegex(ValueError,'NO_SHADOWING'):self.views.observe()
        finally:self.mutate('unmount',target)

    def test_f_actual_rebound_static_file_is_rejected_with_unchanged_host_file_and_docker_config(self):
        target=next(row['destination'] for row in self.gateway['mounts'] if row['source']==str(self.keys['gateway-key']))
        self.mutate('unmount',target)
        self.mutate('bind',target,self.keys['udp-key']);self.mutate('ro',target)
        try:
            self.unchanged_declaration()
            with self.assertRaisesRegex(ValueError,'SOURCE_IDENTITY_OR_ACCESS'):self.views.observe()
        finally:
            self.mutate('unmount',target)
            self.mutate('bind',target,self.keys['gateway-key']);self.mutate('ro',target)

    def test_e_actual_live_permission_drift_is_not_accepted_as_token_renewal(self):
        path=self.auth['gateway']/'token';mode=path.stat().st_mode&0o777;path.chmod(0o400)
        try:
            with self.assertRaisesRegex(ValueError,'LIVE_LEAF_CUSTODY_DIFFERS'):self.views.observe()
        finally:path.chmod(mode)

    def test_z_actual_process_restart_denies_before_mount_observation(self):
        self.command('restart',self.gateway['containerId'])
        with self.assertRaises((ValueError,OSError)):self.views.observe()


if __name__=='__main__':unittest.main()

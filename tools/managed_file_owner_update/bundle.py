"""Seal new adapters with existing Teatri signing/lifecycle/backup/SQL components."""
import importlib.util
from pathlib import Path
def prior():
    path=Path(__file__).resolve().parents[1]/'managed_profile_ths_update/bundle.py';s=importlib.util.spec_from_file_location('retained_single_owner_bundle',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
FILES={**prior().FILES,'entry.py':'scripts/apply-managed-file-owner-v38-20261028.py',
    'database.py':'tools/onboarding_profile_recovery_update/database.py',
    **{n+'.py':'tools/managed_file_owner_update/'+n+'.py'for n in('authority','context','ports','state_fence')}}
def stage(repository,target):
    b=prior().prior();b.FILES=FILES;return b.stage(repository,target)

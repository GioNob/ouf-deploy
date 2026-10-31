"""Seal the new controller and unchanged qualified maintenance building blocks."""
import importlib.util
from pathlib import Path

def prior():
    path=Path(__file__).resolve().parents[1]/'managed_csv_control_update/bundle.py'
    spec=importlib.util.spec_from_file_location('retained_control_bundle',path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

FILES={**prior().FILES,
    'entry.py':'scripts/apply-managed-profile-ths-request-20261028.py',
    'base_authority.py':'tools/managed_csv_control_update/authority.py',
    'control_context.py':'tools/managed_csv_control_update/context.py',
    'control_ports.py':'tools/managed_csv_control_update/ports.py',
    **{n+'.py':'tools/managed_profile_ths_update/'+n+'.py'for n in('authority','context','ports')}}

def stage(repository,target):
    base=prior();base.FILES=FILES
    return base.stage(repository,target)

"""Read new migration host bindings only; never opens a session or requests a grant."""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

CAPSULE_COMMIT='1aa054279ad2d4f21bc27b65585be7dc40cb6f79'
CAPSULE_SHA='e6fe660992f5f018975de73aaf9c83dfe4df9036620257735a5f59b7cf60379d'
CAPSULE_PATH='releases/policy-token-iam-action-source-capsule-20261013.json'
GAP_COMPONENT_HASH='e22d2283d7133eb766b9523e72c4753cb2b67e621c207a3f28fdb79e91090451'
GAP_COMPONENT='IiIiT25lIGZ1dHVyZSBnb3Zlcm5lZCBhdHRlbXB0IHNsb3QsIHByZXNlcnZpbmcgVU5LTk9XTiBsZWdhY3kgYWNjb3VudGluZy4KCkNvbXBvbmVudCBvbmx5LiBObyBncmFudCwgY3JlZGVudGlhbCByZWFkLCBzaWduaW5nLCBydW50aW1lIGluc3RhbGxhdGlvbiBvcgpwZXJtaXNzaW9uIHRvIHN0YXJ0IHRoZSBleGlzdGluZyB3b3JrZXIuIFRoZSBzZWFsZWQgaW5zdGFsbGVyIG11c3QgYmluZCBhY3R1YWwKZXhlY3V0aW5nIGJ5dGVzIGFuZCBhbGwgaW5kZXBlbmRlbnQgY3JlZGVudGlhbC9JQU0vb3duZXIvY3V0b3ZlciBnYXRlcy4KIiIiCmltcG9ydCBmY250bAppbXBvcnQgbWF0aAppbXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzdGF0CmltcG9ydCB0aW1lCmltcG9ydCB1dWlkCmltcG9ydCBpYW1fYmluZGluZ19jYW5kaWRhdGUgYXMgYmluZGluZwpmcm9tIGN1dG92ZXJfYXV0aG9yaXR5IGltcG9ydCBDdXRvdmVyQXV0aG9yaXR5CgpDT05UUkFDVF9IQVNIPSdmMTIwMGI0ZGUwYjMzODk5NzYwYjFkYjE0MDY3MjViNmI3ZDYzMzQ1MWIwMzdlYzlkYzYzODc1NGVjYmNhYTE3JwpHQVBfSEFTSD0nZmJkMzQ0MDhlMzc2YTBhY2E5OGFlZDViYTQxOGJmNTI1OWEzYzM5MGJlMmE0ZWZmZjdkOGJjZTAwN2EyOTdkMScKU1RBVEVTPXsnTkVXX0ZJTklURV9TRVNTSU9OJywnQVRURU1QVF9TTE9UX0NPTlNVTUVEX09VVENPTUVfVU5QUk9WRU4nfQoKZGVmIGJvb3RfaWRlbnRpdHkoKToKICAgIGZkPW9zLm9wZW4oJy9wcm9jL3N5cy9rZXJuZWwvcmFuZG9tL2Jvb3RfaWQnLG9zLk9fUkRPTkxZfG9zLk9fTk9GT0xMT1cpCiAgICB0cnk6CiAgICAgICAgaW5mbz1vcy5mc3RhdChmZCk7cmF3PW9zLnJlYWQoZmQsNjUpCiAgICAgICAgYmluZGluZy5yZXF1aXJlKGluZm8uc3RfdWlkPT1pbmZvLnN0X2dpZD09MCBhbmQgbm90IGluZm8uc3RfbW9kZSYwbzAyMgogICAgICAgICAgICBhbmQgcmUuZnVsbG1hdGNoKHJiJ1swLTlhLWZdezh9LVswLTlhLWZdezR9LVswLTlhLWZdezR9LVswLTlhLWZdezR9LVswLTlhLWZdezEyfVxuJyxyYXcpLAogICAgICAgICAgICAnS0VSTkVMX0JPT1RfSURFTlRJVFlfVU5QUk9WRU4nKQogICAgICAgIHJldHVybiByYXcuZGVjb2RlKCkuc3RyaXAoKQogICAgZmluYWxseTpvcy5jbG9zZShmZCkKCmRlZiBzY29wZShsb2dpY2FsX3Njb3BlX2hhc2gsc291cmNlX2Nsb3N1cmVfaGFzaCk6CiAgICBmb3IgdmFsdWUgaW4gKGxvZ2ljYWxfc2NvcGVfaGFzaCxzb3VyY2VfY2xvc3VyZV9oYXNoKToKICAgICAgICBiaW5kaW5nLnJlcXVpcmUodHlwZSh2YWx1ZSlpcyBzdHIgYW5kIHJlLmZ1bGxtYXRjaCgnWzAtOWEtZl17NjR9Jyx2YWx1ZSksJ0VYQUNUX0dBUF9NSUdSQVRJT05fSEFTSF9SRVFVSVJFRCcpCiAgICByZXR1cm4geydzY2hlbWEnOidvdWYucG9saWN5LXRva2VuLWFjY291bnRpbmctZ2FwLWV4ZWN1dGlvbi1zY29wZS52MScsJ2NvbnRyYWN0SGFzaCc6Q09OVFJBQ1RfSEFTSCwKICAgICAgICAnYWNjb3VudGluZ0dhcEV2aWRlbmNlSGFzaCc6R0FQX0hBU0gsJ2xvZ2ljYWxPd25lclNjb3BlSGFzaCc6bG9naWNhbF9zY29wZV9oYXNoLAogICAgICAgICdzb3VyY2VDbG9zdXJlSGFzaCc6c291cmNlX2Nsb3N1cmVfaGFzaCwnb3BlcmF0aW9uJzonT1BFTl9GSVJTVF9DT05UUk9MTEVEX09XTkVSX1NFU1NJT04nLAogICAgICAgICdsZWdhY3lIaXN0b3J5RGlzcG9zaXRpb24nOidVTktOT1dOX1JFVEFJTkVEX05PVF9SRUNPTkNJTEVEJywnbWF4aW11bUdyYW50QXR0ZW1wdHMnOjEsCiAgICAgICAgJ21heGltdW1FbGFwc2VkU2Vjb25kcyc6MzAwLCdhdXRvbWF0aWNCdWRnZXRSZW5ld2FsQWxsb3dlZCc6RmFsc2UsJ3IxMlJlcGxheUFsbG93ZWQnOkZhbHNlfQoKY2xhc3MgRmlyc3RHYXBTZXNzaW9uOgogICAgZGVmIF9faW5pdF9fKHNlbGYsYXV0aG9yaXR5LGF1dGhvcml0eV9yYXcsbG9naWNhbF9zY29wZV9oYXNoLHNvdXJjZV9jbG9zdXJlX2hhc2gsY2xvY2s9dGltZS50aW1lLG1vbm90b25pYz10aW1lLm1vbm90b25pYyk6CiAgICAgICAgYmluZGluZy5yZXF1aXJlKHR5cGUoYXV0aG9yaXR5KWlzIEN1dG92ZXJBdXRob3JpdHkgYW5kIHR5cGUoYXV0aG9yaXR5X3JhdylpcyBieXRlcywnQ1VSUkVOVF9FWElTVElOR19EVUFMX1JPTEVfQVVUSE9SSVRZX1JFUVVJUkVEJykKICAgICAgICBzZWxmLmF1dGhvcml0eSxzZWxmLnJhdyxzZWxmLmNsb2NrPWF1dGhvcml0eSxieXRlcyhhdXRob3JpdHlfcmF3KSxjbG9jawogICAgICAgIHNlbGYubW9ub3RvbmljPW1vbm90b25pYwogICAgICAgIHNlbGYuc2NvcGU9c2NvcGUobG9naWNhbF9zY29wZV9oYXNoLHNvdXJjZV9jbG9zdXJlX2hhc2gpCiAgICAgICAgYmluZGluZy5yZXF1aXJlKGF1dGhvcml0eS5leHBlY3RlZFsnc291cmNlQ2xvc3VyZUhhc2gnXT09c291cmNlX2Nsb3N1cmVfaGFzaCwnSU5ERVBFTkRFTlRfR0FQX1NPVVJDRV9DTE9TVVJFX1JFUVVJUkVEJykKICAgICAgICAjIFN0YWJsZSBhY3Jvc3MgYXBwcm92YWxzLCBqb2JzIGFuZCByZXN0YXJ0cy4gVGhpcyBpcyBvbmx5IHRoZSBGSVJTVAogICAgICAgICMgbWlncmF0aW9uIHF1YWxpZmljYXRpb24gc2xvdCwgbmV2ZXIgYW4gYXV0b21hdGljIHJlbmV3YWwgQVBJLgogICAgICAgIHNlbGYub3BlcmF0aW9uPWJpbmRpbmcuc2hhKGJpbmRpbmcuZW5jb2RlZCh7J2xvZ2ljYWxTY29wZSc6bG9naWNhbF9zY29wZV9oYXNoLCdjb250cmFjdEhhc2gnOkNPTlRSQUNUX0hBU0gsJ2dhcEhhc2gnOkdBUF9IQVNIfSkpCiAgICAgICAgc2VsZi5uYW1lPSdwb2xpY3ktdG9rZW4tZmlyc3QtZ2FwLXNlc3Npb24tJytzZWxmLm9wZXJhdGlvbisnLnByaXZhdGUuanNvbicKICAgIGRlZiBndWFyZChzZWxmKToKICAgICAgICBiaW5kaW5nLnJlcXVpcmUoYmluZGluZy5kZWNvZGUoc2VsZi5yYXcpLmdldCgncG9saWN5VG9rZW5BY2NvdW50aW5nR2FwTWlncmF0aW9uJyk9PXNlbGYuc2NvcGUsCiAgICAgICAgICAgICdFWFBMSUNJVF9TSUdORURfR0FQX01JR1JBVElPTl9TQ09QRV9SRVFVSVJFRCcpCiAgICAgICAgYmluZGluZy5yZXF1aXJlKHNlbGYuYXV0aG9yaXR5KHNlbGYucmF3KWlzIFRydWUsJ0NVUlJFTlRfSFVNQU5fQU5EX0RVQUxfUk9MRV9BVVRIT1JJVFlfUkVRVUlSRUQnKQogICAgZGVmIHZhbGlkYXRlKHNlbGYscm93KToKICAgICAgICByZXF1aXJlZD17J3NjaGVtYScsJ29wZXJhdGlvbicsJ3Njb3BlJywndmVyc2lvbicsJ3N0YXRlJywnc2Vzc2lvbkRlY2lzaW9uSGFzaCcsJ2NyZWF0ZWRBdCcsJ2xhc3RPYnNlcnZlZEF0JywKICAgICAgICAgICAgJ2V4cGlyZXNBdCcsJ2NyZWF0ZWRNb25vdG9uaWMnLCdsYXN0TW9ub3RvbmljJywnZXhwaXJlc01vbm90b25pYycsJ2Jvb3RJZCcsCiAgICAgICAgICAgICdhdHRlbXB0U2xvdHNDb25zdW1lZCcsJ2xlZ2FjeUhpc3RvcnknLCdoaXN0b3JpY2FsQ3VtdWxhdGl2ZUdyYW50QXR0ZW1wdENvdW50JywKICAgICAgICAgICAgJ3J1bnRpbWVBdXRob3JpdHlJc3N1ZWQnLCdub3RSZWxlYXNlQWNjZXB0YW5jZSd9CiAgICAgICAgYmluZGluZy5yZXF1aXJlKHR5cGUocm93KWlzIGRpY3QgYW5kIHNldChyb3cpPT1yZXF1aXJlZCBhbmQgcm93WydzY2hlbWEnXT09J291Zi5wb2xpY3ktdG9rZW4tZmlyc3QtZ2FwLXNlc3Npb24udjEnCiAgICAgICAgICAgIGFuZCByb3dbJ29wZXJhdGlvbiddPT1zZWxmLm9wZXJhdGlvbiBhbmQgcm93WydzY29wZSddPT1zZWxmLnNjb3BlIGFuZCB0eXBlKHJvd1sndmVyc2lvbiddKWlzIGludCBhbmQgcm93Wyd2ZXJzaW9uJ10+PTAKICAgICAgICAgICAgYW5kIHJvd1snc3RhdGUnXWluIFNUQVRFUyBhbmQgdHlwZShyb3dbJ3Nlc3Npb25EZWNpc2lvbkhhc2gnXSlpcyBzdHIgYW5kIHJlLmZ1bGxtYXRjaCgnWzAtOWEtZl17NjR9Jyxyb3dbJ3Nlc3Npb25EZWNpc2lvbkhhc2gnXSkKICAgICAgICAgICAgYW5kIGFsbCh0eXBlKHJvd1trZXldKWlzIGludCBmb3Iga2V5IGluICgnY3JlYXRlZEF0JywnbGFzdE9ic2VydmVkQXQnLCdleHBpcmVzQXQnLCdhdHRlbXB0U2xvdHNDb25zdW1lZCcpKQogICAgICAgICAgICBhbmQgcm93WydjcmVhdGVkQXQnXTw9cm93WydsYXN0T2JzZXJ2ZWRBdCddPD1yb3dbJ2V4cGlyZXNBdCddCiAgICAgICAgICAgIGFuZCAwPHJvd1snZXhwaXJlc0F0J10tcm93WydjcmVhdGVkQXQnXTw9MzAwIGFuZCByb3dbJ2F0dGVtcHRTbG90c0NvbnN1bWVkJ11pbiAoMCwxKQogICAgICAgICAgICBhbmQgYWxsKHR5cGUocm93W2tleV0paW4gKGZsb2F0LGludClhbmQgbWF0aC5pc2Zpbml0ZShyb3dba2V5XSlhbmQgcm93W2tleV0+PTAKICAgICAgICAgICAgICAgIGZvciBrZXkgaW4gKCdjcmVhdGVkTW9ub3RvbmljJywnbGFzdE1vbm90b25pYycsJ2V4cGlyZXNNb25vdG9uaWMnKSkKICAgICAgICAgICAgYW5kIHJvd1snY3JlYXRlZE1vbm90b25pYyddPD1yb3dbJ2xhc3RNb25vdG9uaWMnXTw9cm93WydleHBpcmVzTW9ub3RvbmljJ10KICAgICAgICAgICAgYW5kIDA8cm93WydleHBpcmVzTW9ub3RvbmljJ10tcm93WydjcmVhdGVkTW9ub3RvbmljJ108PTMwMAogICAgICAgICAgICBhbmQgdHlwZShyb3dbJ2Jvb3RJZCddKWlzIHN0ciBhbmQgcmUuZnVsbG1hdGNoKCdbMC05YS1mLV17MzZ9Jyxyb3dbJ2Jvb3RJZCddKQogICAgICAgICAgICBhbmQgKHJvd1snc3RhdGUnXT09J05FV19GSU5JVEVfU0VTU0lPTicpPT0ocm93WydhdHRlbXB0U2xvdHNDb25zdW1lZCddPT0wKQogICAgICAgICAgICBhbmQgcm93WydsZWdhY3lIaXN0b3J5J109PXsnZ2FwRXZpZGVuY2VIYXNoJzpHQVBfSEFTSCwnc3RhdGUnOidVTktOT1dOJywnY3VtdWxhdGl2ZUdyYW50QXR0ZW1wdENvdW50JzpOb25lLAogICAgICAgICAgICAgICAgJ3JlY29uY2lsZWQnOkZhbHNlLCdnYXBSZW1haW5zT3Blbic6VHJ1ZX0KICAgICAgICAgICAgYW5kIHJvd1snaGlzdG9yaWNhbEN1bXVsYXRpdmVHcmFudEF0dGVtcHRDb3VudCddaXMgTm9uZQogICAgICAgICAgICBhbmQgcm93WydydW50aW1lQXV0aG9yaXR5SXNzdWVkJ11pcyBGYWxzZSBhbmQgcm93Wydub3RSZWxlYXNlQWNjZXB0YW5jZSddaXMgVHJ1ZSwnUkVUQUlORURfR0FQX1NFU1NJT05fRFJJRlQnKQogICAgICAgIHJldHVybiByb3cKICAgIGRlZiBzYXZlKHNlbGYsZGlyZWN0b3J5LHJvdyxmaXJzdD1GYWxzZSk6CiAgICAgICAgcmF3PWJpbmRpbmcuZW5jb2RlZChzZWxmLnZhbGlkYXRlKHJvdykpCiAgICAgICAgaWYgZmlyc3Q6CiAgICAgICAgICAgIGZkPW9zLm9wZW4oc2VsZi5uYW1lLG9zLk9fV1JPTkxZfG9zLk9fQ1JFQVR8b3MuT19FWENMfG9zLk9fTk9GT0xMT1csMG82MDAsZGlyX2ZkPWRpcmVjdG9yeSkKICAgICAgICAgICAgdGVtcD1Ob25lCiAgICAgICAgZWxzZToKICAgICAgICAgICAgdGVtcD0nLicrc2VsZi5uYW1lKycuJyt1dWlkLnV1aWQ0KCkuaGV4CiAgICAgICAgICAgIGZkPW9zLm9wZW4odGVtcCxvcy5PX1dST05MWXxvcy5PX0NSRUFUfG9zLk9fRVhDTHxvcy5PX05PRk9MTE9XLDBvNjAwLGRpcl9mZD1kaXJlY3RvcnkpCiAgICAgICAgdHJ5OgogICAgICAgICAgICB3aXRoIG9zLmZkb3Blbihvcy5kdXAoZmQpLCd3YicpYXMgc3RyZWFtOnN0cmVhbS53cml0ZShyYXcpO3N0cmVhbS5mbHVzaCgpO29zLmZzeW5jKHN0cmVhbS5maWxlbm8oKSkKICAgICAgICAgICAgaWYgdGVtcDpvcy5yZXBsYWNlKHRlbXAsc2VsZi5uYW1lLHNyY19kaXJfZmQ9ZGlyZWN0b3J5LGRzdF9kaXJfZmQ9ZGlyZWN0b3J5KQogICAgICAgICAgICBvcy5mc3luYyhkaXJlY3RvcnkpCiAgICAgICAgICAgIGJpbmRpbmcucmVxdWlyZShiaW5kaW5nLnJlYWRfbWVtYmVyKGRpcmVjdG9yeSxzZWxmLm5hbWUpPT1yYXcsJ0dBUF9TRVNTSU9OX1BVQkxJQ0FUSU9OX1JFQ09OQ0lMSUFUSU9OX1JFUVVJUkVEJykKICAgICAgICBmaW5hbGx5Om9zLmNsb3NlKGZkKQogICAgZGVmIHRyYW5zYWN0aW9uKHNlbGYsY29uc3VtZSk6CiAgICAgICAgc2VsZi5ndWFyZCgpCiAgICAgICAgd2l0aCBiaW5kaW5nLnByb3RlY3RlZF9wYXJlbnQoKWFzIGRpcmVjdG9yeToKICAgICAgICAgICAgZ2FwX25hbWU9J3BvbGljeS10b2tlbi1vd25lci1hY2NvdW50aW5nLW9ic2VydmF0aW9uLScrR0FQX0hBU0grJy5wcml2YXRlLmpzb24nCiAgICAgICAgICAgIGdhcF9yYXc9YmluZGluZy5yZWFkX21lbWJlcihkaXJlY3RvcnksZ2FwX25hbWUpCiAgICAgICAgICAgIGJpbmRpbmcucmVxdWlyZShiaW5kaW5nLnNoYShnYXBfcmF3KT09R0FQX0hBU0gsJ0VYQUNUX1JFVEFJTkVEX0FDQ09VTlRJTkdfR0FQX0hBU0hfUkVRVUlSRUQnKQogICAgICAgICAgICBnYXA9YmluZGluZy5kZWNvZGUoZ2FwX3JhdykKICAgICAgICAgICAgYmluZGluZy5yZXF1aXJlKGdhcC5nZXQoJ3NjaGVtYScpPT0nb3VmLnBvbGljeS10b2tlbi1hY2NvdW50aW5nLXNvdXJjZS1vYnNlcnZhdGlvbi52MScKICAgICAgICAgICAgICAgIGFuZCBnYXAuZ2V0KCdoaXN0b3JpY2FsR3JhbnRBdHRlbXB0Q291bnQnKWlzIE5vbmUgYW5kIGdhcC5nZXQoJ2hpc3RvcmljYWxBY2NvdW50aW5nUmVjb25jaWxlZCcpaXMgRmFsc2UKICAgICAgICAgICAgICAgIGFuZCBnYXAuZ2V0KCdhdWRpdENvbmZpZ3VyYXRpb24nLHt9KS5nZXQoJ2V2ZW50c0VuYWJsZWQnKWlzIEZhbHNlLAogICAgICAgICAgICAgICAgJ0VYQUNUX1VOUkVDT05DSUxFRF9BQ0NPVU5USU5HX0dBUF9SRVFVSVJFRCcpCiAgICAgICAgICAgIGZkPW9zLm9wZW4oc2VsZi5uYW1lKycubG9jaycsb3MuT19SRFdSfG9zLk9fQ1JFQVR8b3MuT19OT0ZPTExPV3xvcy5PX05PTkJMT0NLLDBvNjAwLGRpcl9mZD1kaXJlY3RvcnkpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIGluZm89b3MuZnN0YXQoZmQpCiAgICAgICAgICAgICAgICBiaW5kaW5nLnJlcXVpcmUoc3RhdC5TX0lTUkVHKGluZm8uc3RfbW9kZSlhbmQgaW5mby5zdF91aWQ9PWluZm8uc3RfZ2lkPT0wIGFuZCBzdGF0LlNfSU1PREUoaW5mby5zdF9tb2RlKT09MG82MDAKICAgICAgICAgICAgICAgICAgICBhbmQgaW5mby5zdF9ubGluaz09MSwnR0FQX1NFU1NJT05fRkVOQ0VfQ1VTVE9EWV9SRVFVSVJFRCcpCiAgICAgICAgICAgICAgICBmY250bC5mbG9jayhmZCxmY250bC5MT0NLX0VYfGZjbnRsLkxPQ0tfTkIpCiAgICAgICAgICAgICAgICBiaW5kaW5nLnJlcXVpcmUoYmluZGluZy5pZGVudGl0eShpbmZvKT09YmluZGluZy5pZGVudGl0eShvcy5zdGF0KHNlbGYubmFtZSsnLmxvY2snLGRpcl9mZD1kaXJlY3RvcnksZm9sbG93X3N5bWxpbmtzPUZhbHNlKSksCiAgICAgICAgICAgICAgICAgICAgJ0dBUF9TRVNTSU9OX0ZFTkNFX0NIQU5HRUQnKQogICAgICAgICAgICAgICAgc2VsZi5ndWFyZCgpO25vdz1zZWxmLmNsb2NrKCk7bW9ubz1zZWxmLm1vbm90b25pYygpO2Jvb3Q9Ym9vdF9pZGVudGl0eSgpCiAgICAgICAgICAgICAgICBiaW5kaW5nLnJlcXVpcmUoYWxsKHR5cGUodmFsdWUpaW4gKGludCxmbG9hdClhbmQgbWF0aC5pc2Zpbml0ZSh2YWx1ZSlhbmQgdmFsdWU+PTAgZm9yIHZhbHVlIGluIChub3csbW9ubykpLAogICAgICAgICAgICAgICAgICAgICdHQVBfU0VTU0lPTl9DTE9DS19VTlBST1ZFTicpO25vdz1pbnQobm93KQogICAgICAgICAgICAgICAgdHJ5OnJvdz1zZWxmLnZhbGlkYXRlKGJpbmRpbmcuZGVjb2RlKGJpbmRpbmcucmVhZF9tZW1iZXIoZGlyZWN0b3J5LHNlbGYubmFtZSkpKQogICAgICAgICAgICAgICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgICAgICAgICAgICAgIGJpbmRpbmcucmVxdWlyZShub3QgY29uc3VtZSwnRVhJU1RJTkdfR09WRVJORURfU0VTU0lPTl9SRVFVSVJFRF9OT19JTVBMSUNJVF9DUkVBVElPTicpCiAgICAgICAgICAgICAgICAgICAgc2lnbmVkPWJpbmRpbmcuZGVjb2RlKHNlbGYucmF3KQogICAgICAgICAgICAgICAgICAgIGJpbmRpbmcucmVxdWlyZShzaWduZWRbJ2V4cGlyZXNBdCddPm5vdywnQ1VSUkVOVF9TRVNTSU9OX0FVVEhPUklUWV9SRVFVSVJFRCcpCiAgICAgICAgICAgICAgICAgICAgcm93PXsnc2NoZW1hJzonb3VmLnBvbGljeS10b2tlbi1maXJzdC1nYXAtc2Vzc2lvbi52MScsJ29wZXJhdGlvbic6c2VsZi5vcGVyYXRpb24sJ3Njb3BlJzpzZWxmLnNjb3BlLAogICAgICAgICAgICAgICAgICAgICAgICAndmVyc2lvbic6MCwnc3RhdGUnOidORVdfRklOSVRFX1NFU1NJT04nLCdzZXNzaW9uRGVjaXNpb25IYXNoJzpiaW5kaW5nLnNoYShzZWxmLnJhdyksCiAgICAgICAgICAgICAgICAgICAgICAgICdjcmVhdGVkQXQnOm5vdywnbGFzdE9ic2VydmVkQXQnOm5vdywnZXhwaXJlc0F0JzptaW4obm93KzMwMCxzaWduZWRbJ2V4cGlyZXNBdCddKSwKICAgICAgICAgICAgICAgICAgICAgICAgJ2NyZWF0ZWRNb25vdG9uaWMnOm1vbm8sJ2xhc3RNb25vdG9uaWMnOm1vbm8sCiAgICAgICAgICAgICAgICAgICAgICAgICdleHBpcmVzTW9ub3RvbmljJzptb25vK21pbigzMDAsc2lnbmVkWydleHBpcmVzQXQnXS1ub3cpLCdib290SWQnOmJvb3QsCiAgICAgICAgICAgICAgICAgICAgICAgICdhdHRlbXB0U2xvdHNDb25zdW1lZCc6MCwnbGVnYWN5SGlzdG9yeSc6eydnYXBFdmlkZW5jZUhhc2gnOkdBUF9IQVNILCdzdGF0ZSc6J1VOS05PV04nLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgJ2N1bXVsYXRpdmVHcmFudEF0dGVtcHRDb3VudCc6Tm9uZSwncmVjb25jaWxlZCc6RmFsc2UsJ2dhcFJlbWFpbnNPcGVuJzpUcnVlfSwKICAgICAgICAgICAgICAgICAgICAgICAgJ2hpc3RvcmljYWxDdW11bGF0aXZlR3JhbnRBdHRlbXB0Q291bnQnOk5vbmUsJ3J1bnRpbWVBdXRob3JpdHlJc3N1ZWQnOkZhbHNlLCdub3RSZWxlYXNlQWNjZXB0YW5jZSc6VHJ1ZX0KICAgICAgICAgICAgICAgICAgICBzZWxmLmd1YXJkKCk7c2VsZi5zYXZlKGRpcmVjdG9yeSxyb3csZmlyc3Q9VHJ1ZSk7cmV0dXJuIHJvdwogICAgICAgICAgICAgICAgYmluZGluZy5yZXF1aXJlKG5vdCBjb25zdW1lIG9yIHJvd1snYXR0ZW1wdFNsb3RzQ29uc3VtZWQnXT09MCwnQ09OU1VNRURfU0xPVF9SRVFVSVJFU19SRUNPTkNJTElBVElPTl9OT19SRVBMQVknKQogICAgICAgICAgICAgICAgYmluZGluZy5yZXF1aXJlKHJvd1snbGFzdE9ic2VydmVkQXQnXTw9bm93PHJvd1snZXhwaXJlc0F0J10sJ1NFU1NJT05fRVhQSVJFRF9PUl9DTE9DS19SRUdSRVNTRURfTk9fUkVORVdBTCcpCiAgICAgICAgICAgICAgICBiaW5kaW5nLnJlcXVpcmUocm93Wydib290SWQnXT09Ym9vdCBhbmQgcm93WydsYXN0TW9ub3RvbmljJ108PW1vbm88cm93WydleHBpcmVzTW9ub3RvbmljJ10sCiAgICAgICAgICAgICAgICAgICAgJ1NFU1NJT05fQk9PVF9PUl9NT05PVE9OSUNfRFJJRlRfTk9fUkVORVdBTCcpCiAgICAgICAgICAgICAgICBzZWxmLmd1YXJkKCkKICAgICAgICAgICAgICAgIGlmIGNvbnN1bWU6CiAgICAgICAgICAgICAgICAgICAgcm93LnVwZGF0ZSh2ZXJzaW9uPXJvd1sndmVyc2lvbiddKzEsbGFzdE9ic2VydmVkQXQ9bm93LGxhc3RNb25vdG9uaWM9bW9ubyxhdHRlbXB0U2xvdHNDb25zdW1lZD0xLAogICAgICAgICAgICAgICAgICAgICAgICBzdGF0ZT0nQVRURU1QVF9TTE9UX0NPTlNVTUVEX09VVENPTUVfVU5QUk9WRU4nKQogICAgICAgICAgICAgICAgICAgIGJpbmRpbmcucmVxdWlyZShiaW5kaW5nLnJlYWRfbWVtYmVyKGRpcmVjdG9yeSxnYXBfbmFtZSk9PWdhcF9yYXcsJ0FDQ09VTlRJTkdfR0FQX0VWSURFTkNFX0NIQU5HRUQnKQogICAgICAgICAgICAgICAgICAgIHNlbGYuc2F2ZShkaXJlY3Rvcnkscm93KQogICAgICAgICAgICAgICAgZWxpZiByb3dbJ2F0dGVtcHRTbG90c0NvbnN1bWVkJ109PTA6CiAgICAgICAgICAgICAgICAgICAgcm93LnVwZGF0ZSh2ZXJzaW9uPXJvd1sndmVyc2lvbiddKzEsbGFzdE9ic2VydmVkQXQ9bm93LGxhc3RNb25vdG9uaWM9bW9ubykKICAgICAgICAgICAgICAgICAgICBzZWxmLnNhdmUoZGlyZWN0b3J5LHJvdykKICAgICAgICAgICAgICAgICMgQSBuZXcgYXV0aG9yaXR5L2FwcHJvdmFsIGRvZXMgbm90IGNyZWF0ZSBhbm90aGVyIGZpcnN0IHNsb3QuCiAgICAgICAgICAgICAgICByZXR1cm4gcm93CiAgICAgICAgICAgIGZpbmFsbHk6b3MuY2xvc2UoZmQpCiAgICBkZWYgb3BlbihzZWxmKTpyZXR1cm4gc2VsZi50cmFuc2FjdGlvbihGYWxzZSkKICAgIGRlZiBjb25zdW1lX2F0dGVtcHRfc2xvdChzZWxmKTpyZXR1cm4gc2VsZi50cmFuc2FjdGlvbihUcnVlKQo='
ROOT_BODY=r'''
import base64,hashlib,json,sys,types
raw=sys.stdin.buffer.read(1048577)
if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:raise SystemExit('phase=ROOT_DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH')
p=json.loads(raw)
if type(p)is not dict or set(p)!={'schema','sourceCommit','loader','sources','declarationHash'} or p['schema']!='ouf.policy-token-iam-action-memory-capsule.v1':raise SystemExit('phase=ROOT_DELIVERY reason=EXACT_FULL_CAPSULE_REQUIRED')
loader=base64.b64decode(p['loader'],validate=True)
if not 0<len(loader)<=65536:raise SystemExit('phase=ROOT_DELIVERY reason=LOADER_UNBOUNDED')
sources={n:base64.b64decode(v,validate=True) for n,v in p['sources'].items()}
runtime=types.ModuleType('verified_iam_action_loader')
exec(compile(loader,'verified-iam-action-loader','exec'),runtime.__dict__)
entry,manifest=runtime.load_entry(p['sourceCommit'],sources,loader,p['declarationHash'])
import os,re,stat,signal
binding=entry.binding
report={'schema':'ouf.policy-token-migration-host-review-receipt.v1','status':'BLOCKED',
    'phase':'EXACT_RETAINED_OWNER_AND_GAP_READ','privateEvidenceWrites':0,'credentialFilesRead':0,
    'mountedTokenFilesRead':0,'privateKeyReadCount':0,'installationKeyAccessAttempted':False,
    'signaturesIssued':0,'iamMutations':0,'serviceMutations':0,'tokenGrantRequests':0,'providerCalls':0,
    'iamMetadataGetAttempts':0,'budgetSessionCreated':False,'runtimeAuthorityIssued':False,'productionApplyReady':False,
    'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True,'historicalAccountingReconciled':False,
    'historicalGrantAttemptCount':None,'fullOwnerInstallerQualified':False}
def root_metadata(path):
    rows=[]
    for depth,node in enumerate(reversed((path,*path.parents)),0):
        try:info=node.lstat()
        except FileNotFoundError:return {'path':str(path),'state':'ABSENT','firstMissingDepth':depth,'ancestors':rows,'custodyAccepted':False}
        row={'depth':depth,'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,
            'modeOctal':format(stat.S_IMODE(info.st_mode),'04o'),'symlink':stat.S_ISLNK(info.st_mode),'directory':stat.S_ISDIR(info.st_mode)}
        rows.append(row)
        binding.require(row['directory'] and not row['symlink'] and row['uid']==row['gid']==0 and not info.st_mode&0o022,
            'PROPOSED_MIGRATION_ROOT_ANCESTRY_UNPROVEN')
    return {'path':str(path),'state':'EXISTING_NOT_ACCEPTED','ancestors':rows,'custodyAccepted':False}
try:
    binding.require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
        'ROOT_ISOLATED_MIGRATION_HOST_REVIEW_REQUIRED')
    def deadline(*_):raise binding.CandidateDenied('FINITE_MIGRATION_HOST_REVIEW_DEADLINE')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
    with binding.protected_parent()as directory:
        intake,plan,snapshot,profile=entry.inputs(directory)
        review_hash='8bbc31ce396711acf94ebbc6b541ba60cd99d715315c29736ab697b62b6f78bc'
        review_raw=binding.read_member(directory,'policy-token-iam-action-review-'+review_hash+'.private.json')
        binding.require(binding.sha(review_raw)==review_hash,'RETAINED_OWNER_HOST_REVIEW_DRIFT')
        review=binding.decode(review_raw)
        binding.require(review['sourceClosure']['declaration']==manifest and review['stdlib']==entry.stdlib_binding(),
            'RETAINED_OWNER_SOURCE_OR_STDLIB_DRIFT')
        component_raw=base64.b64decode(GAP_COMPONENT,validate=True)
        binding.require(binding.sha(component_raw)==GAP_COMPONENT_HASH,'GAP_COMPONENT_SOURCE_HASH_DRIFT')
        gap_module=types.ModuleType('qualified_gap_contract_component')
        exec(compile(component_raw,'qualified-gap-contract-component','exec'),gap_module.__dict__)
        gap_name='policy-token-owner-accounting-observation-'+gap_module.GAP_HASH+'.private.json'
        gap_raw=binding.read_member(directory,gap_name)
        binding.require(binding.sha(gap_raw)==gap_module.GAP_HASH,'RETAINED_ACCOUNTING_GAP_HASH_DRIFT')
        gap=binding.decode(gap_raw)
        binding.require(gap.get('schema')=='ouf.policy-token-accounting-source-observation.v1'
            and gap.get('historicalAccountingReconciled')is False and gap.get('historicalGrantAttemptCount')is None
            and gap.get('auditConfiguration',{}).get('eventsEnabled')is False,'EXACT_LEGACY_GAP_REQUIRED')
        report['phase']='SYSTEMCTL_EXECUTABLE_BYTE_BINDING'
        systemctl=entry.governance.executable('/usr/bin/systemctl')
        report['phase']='KERNEL_BOOT_IDENTITY_READ'
        boot=gap_module.boot_identity()
        report['phase']='PROPOSED_MIGRATION_ROOT_METADATA_READ'
        roots={name:root_metadata(binding.Path(path))for name,path in {
            'reviewedCode':'/usr/local/libexec/ouf-policy-token',
            'ownerCredential':'/etc/ouf/policy-token/credentials/semantic',
            'durableRecovery':'/var/lib/ouf/policy-token/semantic'}.items()}
        report['phase']='EXACT_LEGACY_UNIT_STATE_READ'
        import subprocess,tempfile
        with tempfile.TemporaryFile()as stdout,tempfile.TemporaryFile()as stderr:
            result=subprocess.run(['/usr/bin/systemctl','show','ouf-policy-token@semantic.service','ouf-policy-token@semantic.timer',
                '--no-pager','--property=Id,LoadState,ActiveState,UnitFileState,MainPID'],stdin=subprocess.DEVNULL,
                stdout=stdout,stderr=stderr,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            stdout.seek(0);out=stdout.read(8193)
        report['systemctlExitCode']=result.returncode
        binding.require(result.returncode==0 and 0<len(out)<=8192,'EXACT_LEGACY_UNIT_METADATA_UNAVAILABLE')
        units=[]
        for block in out.decode('ascii').strip().split('\n\n'):
            unit={}
            for line in block.splitlines():
                key,sep,value=line.partition('=')
                binding.require(sep and key in {'Id','LoadState','ActiveState','UnitFileState','MainPID'}and key not in unit,'LEGACY_UNIT_METADATA_SCHEMA_UNPROVEN')
                unit[key]=value
            binding.require({'Id','LoadState','ActiveState','UnitFileState'}<=set(unit),'LEGACY_UNIT_METADATA_INCOMPLETE')
            units.append(unit)
        binding.require(len(units)==2 and {u['Id']for u in units}=={'ouf-policy-token@semantic.service','ouf-policy-token@semantic.timer'},
            'EXACT_TWO_LEGACY_UNITS_REQUIRED')
        logical_scope=binding.sha(binding.encoded({'installationRef':entry.governance.CONTEXT['installationRef'],
            'entityRef':entry.governance.CONTEXT['entityRef'],'issuer':snapshot['issuerSelection'],
            'registeredClientUuid':snapshot['client']['id'],'purpose':'SEMANTIC_POLICY_TOKEN_OWNER'}))
        body={'schema':'ouf.policy-token-migration-host-inputs.v1','ownerReviewHash':review_hash,
            'sourceClosureHash':review['sourceClosureHash'],'additionalGapComponentHash':GAP_COMPONENT_HASH,
            'contractHash':gap_module.CONTRACT_HASH,'designApprovedAt':'2026-10-13T17:05:55+02:00',
            'contractDesignApprovalIsNotRuntimeAuthority':True,'gapEvidenceHash':gap_module.GAP_HASH,
            'logicalOwnerScopeHash':logical_scope,'executables':{**intake['executablesProposedNotAccepted'],'systemctl':systemctl},
            'kernelBootId':boot,'proposedRootsMetadata':roots,'legacyUnitsMetadata':units,
            'firstSessionProposal':{'maximumGrantAttempts':1,'maximumElapsedSeconds':300,'budgetIssued':False},
            'legacyHistory':{'state':'UNKNOWN','cumulativeGrantAttemptCount':None,'reconciled':False,'gapRemainsOpen':True},
            'fullOwnerInstallerQualified':False,'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
        binding.require(entry.governance.executable('/usr/bin/systemctl')==systemctl and gap_module.boot_identity()==boot,
            'NATIVE_MIGRATION_HOST_BINDING_CHANGED')
        binding.require({name:root_metadata(binding.Path(value['path']))for name,value in roots.items()}==roots,
            'MIGRATION_ROOT_METADATA_CHANGED')
        binding.require(binding.read_member(directory,gap_name)==gap_raw,'ACCOUNTING_GAP_EVIDENCE_CHANGED')
        raw=binding.encoded(body);digest=binding.sha(raw)
        report['phase']='PRIVATE_MIGRATION_HOST_REVIEW_PUBLICATION'
        name='policy-token-migration-host-inputs-'+digest+'.private.json'
        wrote=entry.publish(directory,name,raw)
        report.update(status='MIGRATION_HOST_INPUTS_PREPARED_NOT_ACCEPTED',phase='PREPARED_NOT_ACCEPTED',
            privateEvidenceWrites=int(wrote),privateEvidenceHash=digest,privateEvidencePath=str(binding.PARENT/name),
            systemctlExecutableBound=True,kernelBootIdentityObserved=True,roots={name:{'state':value['state'],'custodyAccepted':False}for name,value in roots.items()},
            units=units,maximumProposedGrantAttempts=1,maximumProposedElapsedSeconds=300)
    code=0
except Exception as error:
    reason=str(error)
    report.update(reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else type(error).__name__,
        evidencePublicationMayBePartial=report['phase']=='PRIVATE_MIGRATION_HOST_REVIEW_PUBLICATION')
    if isinstance(error,OSError):report['errno']=error.errno
    code=1
finally:signal.alarm(0)
print(binding.encoded(report).decode());raise SystemExit(code)
'''

def main():
    if not re.fullmatch('[0-9a-f]{40}',CAPSULE_COMMIT) or not re.fullmatch('[0-9a-f]{64}',CAPSULE_SHA):
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_NOT_QUALIFIED; no sudo executed')
    preferred=Path.home()/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
    gh=str(preferred) if preferred.is_file() and os.access(preferred,os.X_OK) else shutil.which('gh')
    if not gh:raise SystemExit('phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE; no sudo executed')
    endpoint='repos/GioNob/ouf-deploy/contents/'+CAPSULE_PATH+'?ref='+CAPSULE_COMMIT
    try:
        result=subprocess.run([gh,'api',endpoint,'--jq','.content'],check=True,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,timeout=30)
        if len(result.stdout)>1500000:raise ValueError()
        raw=base64.b64decode(b''.join(result.stdout.split()),validate=True)
    except Exception:raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_UNAVAILABLE; no sudo executed') from None
    if not 0<len(raw)<=1048576 or hashlib.sha256(raw).hexdigest()!=CAPSULE_SHA:
        raise SystemExit('phase=DELIVERY reason=FULL_CAPSULE_HASH_MISMATCH; no sudo executed')
    root_code='CAPSULE_SHA='+repr(CAPSULE_SHA)+'\nGAP_COMPONENT_HASH='+repr(GAP_COMPONENT_HASH)+'\nGAP_COMPONENT='+repr(GAP_COMPONENT)+'\n'+ROOT_BODY
    try:return subprocess.run(['sudo','--','/usr/bin/python3','-I','-B','-S','-c',root_code],input=raw,timeout=140).returncode
    except Exception:raise SystemExit('phase=ROOT_EXECUTION reason=MIGRATION_HOST_REVIEW_RESULT_UNAVAILABLE; preserve output, do not automatically rerun') from None

if __name__=='__main__':raise SystemExit(main())

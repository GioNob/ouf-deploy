#!/usr/bin/env python3
"""Probe the installed UDP S3 factory/adapter on private SeaweedFS, without Spring.

Reads allowlisted source JSON properties. One temporary container, one new small
diagnostic object. No app restart/binding change, database access or source PUT.
"""
import base64
import configparser
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid
import zipfile

ROOT = Path('/var/lib/ouf-storage-migration')
BINDINGS = ROOT / 'seaweedfs/staging-oci33-20261107-v1/application-s3-v1'
CID = '946fd69972ada2e310c32f72da27f19a04e7a2043dc330f116e8ba1c507e6e3b'
IMAGE = 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'
SEA_IMAGE = 'sha256:d23a50eb6cf56dc994ddc10f43590cc9a8a22a20019cab36d4ad00c3ad3b4af2'
NETWORK, SEA, BUCKET = 'ouf-seaweedfs-private', 'ouf-seaweedfs-stage', 'ouf-udp'
ENDPOINT = 'https://ouf-seaweedfs-stage:9002'
CA_SHA = 'c1ab769d4b76565f717e2600266e11afd0f2042829f486f22fe8596f369cbccf'
DOCKER = ('/usr/bin/docker', '--host', 'unix:///run/docker.sock', '--config', '/nonexistent')
PAYLOAD = b'id,label\n1,ouf-udp-storage-probe\n'
CLASS_SHA = 'acab7bfc5ce9c4e7b9ca7e66a179832a53532119787b0ad631ba671f532c0357'
CLASS_B64 = 'yv66vgAAAD0BgQoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClWCAAIAQAZW0EtWmEtejAtOV8uJDovIC1dezEsMTYwfQoACgALBwAMDAANAA4BABBqYXZhL2xhbmcvU3RyaW5nAQAHbWF0Y2hlcwEAFShMamF2YS9sYW5nL1N0cmluZzspWhIAAAAQDAARABIBABdtYWtlQ29uY2F0V2l0aENvbnN0YW50cwEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7CAAUAQAEbnVsbAoAFgAXBwAYDAAZABoBABNqYXZhL3V0aWwvSGV4Rm9ybWF0AQACb2YBABcoKUxqYXZhL3V0aWwvSGV4Rm9ybWF0OwgAHAEAB1NIQS0yNTYKAB4AHwcAIAwAIQAiAQAbamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0AQALZ2V0SW5zdGFuY2UBADEoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3Q7CgAeACQMACUAJgEABmRpZ2VzdAEABihbQilbQgoAFgAoDAApACoBAAlmb3JtYXRIZXgBABYoW0IpTGphdmEvbGFuZy9TdHJpbmc7CgAsAC0HAC4MAC8AMAEAD2phdmEvbGFuZy9DbGFzcwEADWdldFNpbXBsZU5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOxIAAQAQCgAsADMMADQANQEAE2dldFJlc291cmNlQXNTdHJlYW0BACkoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2lvL0lucHV0U3RyZWFtOwcANwEAH2phdmEvbGFuZy9JbGxlZ2FsU3RhdGVFeGNlcHRpb24IADkBABZDTEFTU19SRVNPVVJDRV9NSVNTSU5HCgA2ADsMAAUAPAEAFShMamF2YS9sYW5nL1N0cmluZzspVgoAPgA/BwBADABBAEIBABNqYXZhL2lvL0lucHV0U3RyZWFtAQAMcmVhZEFsbEJ5dGVzAQAEKClbQgoARABFBwBGDABHACoBABVVZHBTdG9yYWdlQ2xpZW50UHJvYmUBAARoYXNoCgA+AEkMAEoABgEABWNsb3NlBwBMAQATamF2YS9sYW5nL1Rocm93YWJsZQoASwBODABPAFABAA1hZGRTdXBwcmVzc2VkAQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWCQBSAFMHAFQMAFUAVgEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsSAAIAEAoAWQBaBwBbDABcADwBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbggAXgEACVBSRUZMSUdIVAgAYAEABWNoZWNrCABiAQADcnVuCwBkAGUHAGYMABkAZwEADmphdmEvdXRpbC9MaXN0AQA2KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS91dGlsL0xpc3Q7CwBkAGkMAGoAawEACGNvbnRhaW5zAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaCABtAQAHb3VmLXVkcAoACgBvDABwAGsBAAZlcXVhbHMIAHIBACpkaWFnbm9zdGljcy9zZWF3ZWVkZnMtY2xpZW50L1thLWYwLTktXXszNn0HAHQBACJqYXZhL2xhbmcvSWxsZWdhbEFyZ3VtZW50RXhjZXB0aW9uCgBzAAMIAHcBABAvcHJvYmUvaW5wdXQuY3N2CwB5AHoHAHsMABkAfAEAEmphdmEvbmlvL2ZpbGUvUGF0aAEAOyhMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL25pby9maWxlL1BhdGg7CgB+AH8HAIAMAEEAgQEAE2phdmEvbmlvL2ZpbGUvRmlsZXMBABgoTGphdmEvbmlvL2ZpbGUvUGF0aDspW0IKACwAgwwAhACFAQAOZ2V0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7CACHAQAtaXQuY29tdW5lLnRyaWVzdGUub3VmLnVkcC5TM0xha2VDb25maWd1cmF0aW9uCgAsAIkMAIoAiwEAB2Zvck5hbWUBAD0oTGphdmEvbGFuZy9TdHJpbmc7WkxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7KUxqYXZhL2xhbmcvQ2xhc3M7CACNAQA0aXQuY29tdW5lLnRyaWVzdGUub3VmLnVkcC5TM0xha2VPYmplY3RTdG9yYWdlQWRhcHRlcgoARACPDACQAJEBAAljbGFzc0hhc2gBACUoTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9TdHJpbmc7CACTAQBANTAzNjE2MGJiZDQ2ODA5ZWU4N2FkYjI4NWU0ODk1NDdmYzBhNzEzZTk3YTg1MzI3ZDYwOTdiZTU5YjE1MzBlNggAlQEAQDVhNmJkODcxY2UwMWUyMjM1YWI5OGY3NGU2MzA3MDE2ZWJlYzk5OTZlNjJlNDJmY2NjMTFjYTk1MWVhYTdiZjgIAJcBABdJTlNUQUxMRURfQ0xBU1NfQ0hBTkdFRAgAmQEADGxha2VTM0NsaWVudAkAmwCcBwCdDACeAJ8BABFqYXZhL2xhbmcvQm9vbGVhbgEABFRZUEUBABFMamF2YS9sYW5nL0NsYXNzOwoALAChDACiAKMBABFnZXREZWNsYXJlZE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsKAKUApgcApwwAqACpAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kAQANc2V0QWNjZXNzaWJsZQEABChaKVYKACwAqwwArACtAQAOZ2V0Q29uc3RydWN0b3IBADMoW0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9Db25zdHJ1Y3RvcjsKAK8AsAcAsQwAsgCzAQAdamF2YS9sYW5nL3JlZmxlY3QvQ29uc3RydWN0b3IBAAtuZXdJbnN0YW5jZQEAJyhbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgAtQEACXVzLWVhc3QtMQgAtwEAIGh0dHBzOi8vb3VmLXNlYXdlZWRmcy1zdGFnZTo5MDAyCgCbALkMALoAuwEAB3ZhbHVlT2YBABYoWilMamF2YS9sYW5nL0Jvb2xlYW47CgClAL0MAL4AvwEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwgAwQEAK3NvZnR3YXJlLmFtYXpvbi5hd3NzZGsuc2VydmljZXMuczMuUzNDbGllbnQKACwAwwwAigDEAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwcAxgEAFGphdmEvdXRpbC9Qcm9wZXJ0aWVzCgDFAAMIAMkBADdNRVRBLUlORi9tYXZlbi9zb2Z0d2FyZS5hbWF6b24uYXdzc2RrL3MzL3BvbS5wcm9wZXJ0aWVzCgDLADMHAMwBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIKAMUAzgwAzwDQAQAEbG9hZAEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgoARADSDADTABIBAAVxdW90ZQgA1QEADGphdmEudmVyc2lvbgoAUgDXDADYABIBAAtnZXRQcm9wZXJ0eQgA2gEAB3ZlcnNpb24KAMUA1xIAAwDdDAARAN4BAFwoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoARADgDADhADwBAARlbWl0CABKCgAsAOQMAOUAowEACWdldE1ldGhvZAcA5wEAJmphdmEvbGFuZy9SZWZsZWN0aXZlT3BlcmF0aW9uRXhjZXB0aW9uEgAEABAIAOoBABBDSEVDS19LRVlfQUJTRU5UCADsAQAEaGVhZAcA7gEAEmphdmEvdXRpbC9PcHRpb25hbAoA7QDwDADxAPIBAAlpc1ByZXNlbnQBAAMoKVoIAPQBABVESUFHTk9TVElDX0tFWV9FWElTVFMIAPYBAAxQVVRfQU5EX0hFQUQIAPgBAANwdXQHAPoBAAJbQggA/AEACHRleHQvY3N2CAD+AQA8aXQuY29tdW5lLnRyaWVzdGUub3VmLnVkcC5MYWtlT2JqZWN0U3RvcmFnZVBvcnQkU3RvcmVkT2JqZWN0CAEAAQAHbG9jYXRvcggBAgEAC2NvbnRlbnRIYXNoCAEEAQAJc2l6ZUJ5dGVzBwEGAQAOamF2YS9sYW5nL0xvbmcKAQUBCAwBCQEKAQAJbG9uZ1ZhbHVlAQADKClKCAEMAQAHZHVyYWJsZQoAmwEODAEPAPIBAAxib29sZWFuVmFsdWUIAREBAANHRVQIARMBAARyZWFkCgEVARYHARcMAHABGAEAEGphdmEvdXRpbC9BcnJheXMBAAcoW0JbQilaCAEaAQASUFVUX0hFQURfR0VUX01BVENICAEcAQAcQ09OVEVOVF9PUl9NRVRBREFUQV9NSVNNQVRDSBIABQEeDAARAR8BADsoTGphdmEvbGFuZy9TdHJpbmc7WlpJTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwoAUgEhDAEiASMBAARleGl0AQAEKEkpVgcBJQEAE2phdmEvdXRpbC9BcnJheUxpc3QKASQAAwsAZAEoDAEpASoBAARzaXplAQADKClJBwEsAQAramF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvblRhcmdldEV4Y2VwdGlvbgoAAgEuDAEvATABAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsKACwBMgwBMwAwAQAHZ2V0TmFtZQsAZAE1DAE2AGsBAANhZGQIATgBAApzdGF0dXNDb2RlBwE6AQARamF2YS9sYW5nL0ludGVnZXIIATwBAA9hd3NFcnJvckRldGFpbHMIAT4BAAllcnJvckNvZGUKAEsBQAwBQQFCAQAIZ2V0Q2F1c2UBABcoKUxqYXZhL2xhbmcvVGhyb3dhYmxlOwgBRAEAASwKAAoBRgwBRwFIAQAEam9pbgEAQChMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTtMamF2YS9sYW5nL0l0ZXJhYmxlOylMamF2YS9sYW5nL1N0cmluZzsKATkBSgwBSwEqAQAIaW50VmFsdWUKAAoBTQwAugFOAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL1N0cmluZzsSAAYBUAwAEQFRAQBdKExqYXZhL2xhbmcvU3RyaW5nO1pMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAGQ09ORklHAQASTGphdmEvbGFuZy9TdHJpbmc7AQANQ29uc3RhbnRWYWx1ZQEAB0FEQVBURVIBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQANU3RhY2tNYXBUYWJsZQEACkV4Y2VwdGlvbnMHAVsBABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAJU2lnbmF0dXJlAQAoKExqYXZhL2xhbmcvQ2xhc3M8Kj47KUxqYXZhL2xhbmcvU3RyaW5nOwEABG1haW4BABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWBwFhAQATW0xqYXZhL2xhbmcvU3RyaW5nOwcBYwEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAKU291cmNlRmlsZQEAGlVkcFN0b3JhZ2VDbGllbnRQcm9iZS5qYXZhAQAQQm9vdHN0cmFwTWV0aG9kcw8GAWgKAWkBagcBawwAEQFsAQAkamF2YS9sYW5nL2ludm9rZS9TdHJpbmdDb25jYXRGYWN0b3J5AQCYKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL2ludm9rZS9DYWxsU2l0ZTsIAW4BAAMiASIIAXABAAcBLmNsYXNzCAFyAQAPT1VGX1VEUF9QUk9CRSABCAF0AQBxeyJzdGF0dXMiOiJKQVZBX0NMSUVOVF9SRUFEWSIsImNvbmZpZ3VyYXRpb25DbGFzc1NoYTI1NiI6ASwiYWRhcHRlckNsYXNzU2hhMjU2IjoBLCJqYXZhVmVyc2lvbiI6ASwic2RrVmVyc2lvbiI6AX0IAXYBAAhzaGEyNTY6AQgBeAEAZHsic3RhdHVzIjoBLCJwdXRBY2tub3dsZWRnZWQiOnRydWUsIm1ldGFkYXRhTWF0Y2hlcyI6ASwiYm9keU1hdGNoZXMiOgEsImJvZHlCeXRlcyI6ASwiYm9keVNoYTI1NiI6AX0IAXoBAHx7InN0YXR1cyI6IkpBVkFfQ0xJRU5UX0ZBSUxFRCIsInBoYXNlIjoBLCJwdXRBY2tub3dsZWRnZWQiOgEsImV4Y2VwdGlvbkNsYXNzZXMiOlsBXSwicHJvdmlkZXJDb2RlIjoBLCJwcm92aWRlckh0dHBTdGF0dXMiOgF9AQAMSW5uZXJDbGFzc2VzBwF9AQAlamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAcBfwEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwEABkxvb2t1cAAxAEQAAgAAAAIAGgFSAVMAAQFUAAAAAgCGABoBVQFTAAEBVAAAAAIAjAAGAAEABQAGAAEBVgAAAB0AAQABAAAABSq3AAGxAAAAAQFXAAAABgABAAAADAAKANMAEgABAVYAAAA+AAIAAQAAABkqxgAVKhIHtgAJmQAMKroADwAApwAFEhOwAAAAAgFXAAAABgABAAAAEAFYAAAABwACFkEHAAoACgBHACoAAgFWAAAAKAADAAEAAAAQuAAVEhu4AB0qtgAjtgAnsAAAAAEBVwAAAAYAAQAAABMBWQAAAAQAAQFaAAoAkACRAAMBVgAAALYAAwAEAAAAQioqtgArugAxAAC2ADJMK8cADbsANlkSOLcAOr8rtgA9uABDTSvGAAcrtgBILLBNK8YAECu2AEinAAlOLC22AE0svwACAA4AJAAuAEsAMwA3ADoASwACAVcAAAAaAAYAAAAWAA4AFwAcABgAJAAZACwAGAAuABYBWAAAADIABfwAHAcAPvwADwcACv8AAQACBwAsBwA+AAEHAEv/AAsAAwcALAcAPgcASwABBwBLBQFZAAAABAABAVoBXAAAAAIBXQAKAOEAPAABAVYAAAAlAAIAAQAAAA2yAFEqugBXAAC2AFixAAAAAQFXAAAABgABAAAAGwAJAV4BXwABAVYAAAgsAAcAFwAABJgSXUwDPQFOKr4GoAArEl8SYbgAYyoDMrkAaAIAmQAZKgQyEmy2AG6ZAA4qBTIScbYACZoAC7sAc1m3AHW/EnYDvQAKuAB4uAB9OgQZBL4EoQAMGQS+ERAApAALuwBzWbcAdb8SRLYAgjoFEoYDGQW4AIg6BhKMAxkFuACIOgcZBrgAjjoIGQe4AI46CRkIEpK2AG6ZAA0ZCRKUtgBumgANuwA2WRKWtwA6vxkGEpgGvQAsWQMSClNZBBIKU1kFsgCaU7YAoDoKGQoEtgCkGQoZBgO9ACy2AKoDvQACtgCuBr0AAlkDErRTWQQStlNZBQS4ALhTtgC8ThLAuADCOgsZBwW9ACxZAxkLU1kEEgpTtgCqBb0AAlkDLVNZBCoEMlO2AK46DCoDMhJftgBumQCOuwDFWbcAxzoNGQUSyLYAyjoOGQ7GAAoZDRkOtgDNGQ7GACYZDrYASKcAHjoPGQ7GABQZDrYASKcADDoQGQ8ZELYATRkPvxkIuADRGQm4ANES1LgA1rgA0RkNEtm2ANu4ANG6ANwAALgA3y3GAB8SwLgAwhLiA70ALLYA4y0DvQACtgC8V6cABToOsRkEuABDugDoAAA6DRLpTBkHEusEvQAsWQMSClO2AOMZDAS9AAJZAyoFMlO2ALw6DhkOwADttgDvmQANuwA2WRLztwA6vxL1TBkHEvcHvQAsWQMSClNZBBL5U1kFEgpTWQYSClO2AOMZDAe9AAJZAyoFMlNZBBkEU1kFEvtTWQYZDVO2ALw6DwQ9Ev24AMI6ECoFMhkQEv8DvQAstgDjGQ8DvQACtgC8tgBumQBlGQ0ZEBMBAQO9ACy2AOMZDwO9AAK2ALy2AG6ZAEgZEBMBAwO9ACy2AOMZDwO9AAK2ALzAAQW2AQcZBL6FlJoAJRkQEwELA70ALLYA4xkPA70AArYAvMAAm7YBDZkABwSnAAQDNhETARBMGQcTARIEvQAsWQMSClO2AOMZDAS9AAJZAyoFMlO2ALzAAPk6EhkEGRK4ARQ2ExURmQAMFROZAAcEpwAEAzYUFRSZAAkTARmnAAYTARu4ANEVERUTGRK+GRK4AEO4ANG6AR0AALgA3xUUmgAHBbgBIC3GAVUSwLgAwhLiA70ALLYA4y0DvQACtgC8V6cBOzoEpwE2OgS7ASRZtwEmOgUBOgYBOgcZBDoIGQjGAJIZBbkBJwEAEAyiAIYZCMEBK5oAFhkFGQi2AS22ATG4ANG5ATQCAFcZCLYBLRMBNwO9ACy2AOMZCAO9AAK2ALzAATk6BxkItgEtEwE7A70ALLYA4xkIA70AArYAvDoJGQnGACAZCbYBLRMBPQO9ACy2AOMZCQO9AAK2ALzAAAo6BqcABToJGQi2AT86CKf/byu4ANEcEwFDGQW4AUUZBrgA0RkHxgAdGQe2AUkQZKEAExkHtgFJEQJXowAIGQenAAUSE7gBTLoBTwAAuADfBbgBIC3GAEcSwLgAwhLiA70ALLYA4y0DvQACtgC8V6cALToEpwAoOhUtxgAfEsC4AMIS4gO9ACy2AOMtA70AArYAvFenAAU6FhkVv7EADQFCAU4BWwBLAWIBZwFqAEsBngG1AbgA5gNFA1wDXwDmAAcBmgNkAEsBuwNBA2QASwOlA/4EAQDmBFMEagRtAOYABwGaBHIAAAG7A0EEcgAAA2QETwRyAAAEeASPBJIA5gRyBHQEcgAAAAIBVwAAAVIAVAAAAB0AAwAeAAUAHwAHACEAJAAiAC8AIwA9ACQASwAlAGMAJgBqACcAdAAoAH4AKQCMACoAmgArAKAALACqAC0AxwAuAM0ALwD4ADAA/wAxASUAMgEwADMBOQA0AUIANQFOADYBWwA0AXYANwF9ADgBggA5AYwAOgGXADcBmgBlAZ4AZgG1AGcBugA7AbsAPQHHAD4BygA/AesAQAIAAEECAwBCAj0AQwJCAEQCRABFAksARgJzAEcCjgBIArEASQLNAEoC0QBLAvYATAL/AE0DEABOAyoAUQM1AE4DOABSA0EAZQNFAGYDXABnA2QAUwNmAFQDbwBVA3IAVgN1AFcDigBYA6UAWgPCAFsD3ABcA/4AXQQDAFcEDQBfBBcAYAQcAGEEHwBiBEgAXwRLAGMETwBlBFMAZgRqAGcEcgBlBHgAZgSPAGcElABpBJcAagFYAAABwgAl/gA1BwAKAQcAAgf8AB0HAPkH/wA8AAoHAWAHAAoBBwACBwD5BwDLBwAsBwAsBwAKBwAKAAAJ/wCjAA8HAWAHAAoBBwACBwD5BwDLBwAsBwAsBwAKBwAKBwClBwAsBwACBwDFBwA+AABMBwBL/wAOABAHAWAHAAoBBwACBwD5BwDLBwAsBwAsBwAKBwAKBwClBwAsBwACBwDFBwA+BwBLAAEHAEsI+QAC9wBBBwDmAfoAAP0ARAcACgcAAv0AyQcAAgcALEAB/gBBAQcA+QFAAfwADAFCBwAK/wAiAAQHAWAHAAoBBwACAABdBwDmRAcAS/8AFAAJBwFgBwAKAQcAAgcASwcAZAcACgcBOQcASwAAK/sAWEIHAOYB+gAJ/wAwAAgHAWAHAAoBBwACBwBLBwBkBwAKBwE5AAQHAAoBBwAKBwAK/wABAAgHAWAHAAoBBwACBwBLBwBkBwAKBwE5AAUHAAoBBwAKBwAKBwFi/wAsAAQHAWAHAAoBBwACAAEHAOZEBwBL/wAfABYHAWAHAAoBBwACAAAAAAAAAAAAAAAAAAAAAAAHAEsAAQcA5gH/AAIABAcBYAcACgEHAAIAAAADAWQAAAACAWUBZgAAACwABwFnAAEBbQFnAAEBbwFnAAEBcQFnAAEBcwFnAAEBdQFnAAEBdwFnAAEBeQF7AAAACgABAXwBfgGAABk='
ADAPTER_HASHES = {'S3LakeConfiguration': '5036160bbd46809ee87adb285e489547fc0a713e97a85327d6097be59b1530e6',
                  'S3LakeObjectStorageAdapter': '5a6bd871ce01e2235ab98f74e6307016ebec9996e62e42fccc11ca951eaa7bf8'}
DEADLINE = 0
SAFE_CODES = set()


def need(ok, code):
    SAFE_CODES.add(code)
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=1024 * 1024):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    need(len(raw) <= limit, 'INPUT_TOO_LARGE')
    return raw


def docker(*args, timeout=20, checked=True):
    remaining = DEADLINE - time.monotonic()
    need(remaining > 0, 'PROBE_DEADLINE')
    p = subprocess.run((*DOCKER, *args), capture_output=True, timeout=min(timeout, remaining))
    need(len(p.stdout) + len(p.stderr) <= 4 * 1024 * 1024, 'COMMAND_OUTPUT_LIMIT')
    if checked:
        need(p.returncode == 0, 'DOCKER_COMMAND_FAILED')
    return p


def inspect(ref):
    docs = json.loads(docker('container', 'inspect', ref).stdout)
    need(len(docs) == 1, 'CONTAINER_NOT_UNIQUE')
    return docs[0]


def env(doc):
    rows = doc['Config'].get('Env') or []
    values = dict(row.split('=', 1) for row in rows if '=' in row)
    need(len(rows) == len(values), 'ENVIRONMENT_NOT_UNIQUE')
    return values


def safe_setting(field, value):
    if value is None:
        return None
    if field == 'path-style' and isinstance(value, bool):
        return value
    if field == 'endpoint':
        if not isinstance(value, str):
            return '<noncanonical-or-sensitive>'
        try:
            u = urlsplit(value)
            need(u.scheme in ('http', 'https') and u.hostname and
                 re.fullmatch(r'[A-Za-z0-9._:-]{1,253}', u.hostname) and
                 not (u.username or u.password or u.query or u.fragment or u.path not in ('', '/')),
                 'JSON_ENDPOINT_NOT_SAFE_TO_EMIT')
            return {'scheme': u.scheme, 'host': u.hostname, 'port': u.port}
        except (ValueError, TypeError, RuntimeError):
            return '<noncanonical-or-sensitive>'
    pattern = {'bucket': r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',
               'region': r'[a-z0-9-]{1,40}', 'path-style': r'true|false'}[field]
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else '<noncanonical>'


def source_json_storage(value):
    if not value:
        return {'present': False, 'storageDeclarations': []}
    need(len(value) <= 1024 * 1024, 'SOURCE_JSON_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, val in pairs:
            need(key not in result, 'SOURCE_JSON_DUPLICATE_KEY')
            result[key] = val
        return result
    parsed = json.loads(value, object_pairs_hook=unique)
    need(isinstance(parsed, dict), 'SOURCE_JSON_NOT_OBJECT')
    selected = []
    def walk(node, prefix='', depth=0):
        need(depth <= 20, 'SOURCE_JSON_TOO_DEEP')
        for key, val in node.items():
            name = prefix + key
            if isinstance(val, dict):
                walk(val, name + '.', depth + 1)
            else:
                for field in ('endpoint', 'bucket', 'region', 'path-style'):
                    if name in ('ouf.udp.lake.s3.' + field,
                                'OUF_UDP_S3_' + field.upper().replace('-', '_')):
                        selected.append({'property': name, 'value': safe_setting(field, val)})
    walk(parsed)
    return {'present': True, 'storageDeclarations': selected,
            'meaning': 'DECLARED_JSON_PROPERTIES_NOT_COMPLETE_EFFECTIVE_SPRING_CONFIGURATION'}


def original_jar(app):
    args = app.get('Args') or []
    need(Path(app.get('Path', '')).name == 'java' and args.count('-jar') == 1
         and args[args.index('-jar') + 1] == '/app/app.jar', 'OBSERVED_UDP_LAUNCH_CHANGED')
    pid = app['State']['Pid']
    need(isinstance(pid, int) and pid > 0, 'UDP_PID_REQUIRED')
    path = Path('/proc') / str(pid) / 'root/app/app.jar'
    need(path.stat().st_size <= 512 * 1024 * 1024, 'JAR_TOO_LARGE')
    with zipfile.ZipFile(path) as jar:
        for name, expected in ADAPTER_HASHES.items():
            item = jar.getinfo('BOOT-INF/classes/it/comune/trieste/ouf/udp/' + name + '.class')
            need(item.file_size <= 256 * 1024 and sha(jar.read(item)) == expected, 'INSTALLED_ADAPTER_CHANGED')
        need('BOOT-INF/lib/s3-2.54.17.jar' in jar.namelist(), 'INSTALLED_SDK_CHANGED')
        launchers = [name for name in ('org.springframework.boot.loader.launch.PropertiesLauncher',
                                       'org.springframework.boot.loader.PropertiesLauncher')
                     if name.replace('.', '/') + '.class' in jar.namelist()]
        need(len(launchers) == 1, 'BOOT_PROPERTIES_LAUNCHER_NOT_UNIQUE')
        return launchers[0]


def java(cid, launcher, mode, key):
    p = docker('exec', cid, 'java', '-Xmx192m',
               '-Djavax.net.ssl.trustStore=/tmp/probe.p12', '-Djavax.net.ssl.trustStorePassword=changeit',
               '-Dloader.main=UdpStorageClientProbe', '-Dloader.path=/probe',
               '-Dloader.config.location=file:/probe/loader.properties',
               '-cp', '/app/app.jar', launcher, mode, BUCKET, key,
               timeout=95, checked=False)
    rows = [line[len(b'OUF_UDP_PROBE '):] for line in p.stdout.splitlines() if line.startswith(b'OUF_UDP_PROBE ')]
    if len(rows) != 1:
        return {'status': 'JAVA_LAUNCH_FAILED', 'exitCode': p.returncode}
    result = json.loads(rows[0])
    result['exitCode'] = p.returncode
    return result


def run(report):
    global DEADLINE
    DEADLINE = time.monotonic() + 230
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    app = inspect(CID)
    need(app['State']['Running'] and app['Image'] == IMAGE, 'UDP_RUNNING_IMAGE_CHANGED')
    identity = (app['Id'], app['Image'], app['State']['StartedAt'])
    report['sourceApplicationJsonStorage'] = source_json_storage(env(app).get('SPRING_APPLICATION_JSON'))
    launcher = original_jar(app)
    sea = inspect(SEA)
    need(sea['State']['Running'] and sea['Image'] == SEA_IMAGE
         and set(sea['NetworkSettings']['Networks']) == {NETWORK}
         and not sea['HostConfig'].get('PortBindings'), 'SEAWEEDFS_BINDING_CHANGED')
    need(any(m['Source'] == str(BINDINGS / 'config') and m['Destination'] == '/config' and not m['RW']
             for m in sea['Mounts']), 'SEAWEEDFS_CONFIG_MOUNT_CHANGED')
    network = json.loads(docker('network', 'inspect', NETWORK).stdout)[0]
    need(network['Internal'], 'PRIVATE_NETWORK_REQUIRED')
    image = json.loads(docker('image', 'inspect', IMAGE).stdout)[0]
    baked = env(image)
    need(not any(k.startswith(('AWS_', 'SPRING_')) or k in ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS')
                 for k in baked), 'IMAGE_ENVIRONMENT_REQUIRES_REVIEW')
    target = json.loads(read(BINDINGS / 'clients/udp/binding.private.json'))['environment']
    need(target['OUF_UDP_S3_ENDPOINT'] == ENDPOINT and target['OUF_UDP_S3_BUCKET'] == BUCKET
         and target['OUF_UDP_S3_REGION'] == 'us-east-1' and target['OUF_UDP_S3_PATH_STYLE'] == 'true',
         'PREPARED_TARGET_CHANGED')
    credentials = read(BINDINGS / 'clients/udp/credentials', 16384)
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(credentials.decode())
    need(set(config.sections()) == {'default'} and not config.defaults()
         and set(config['default']) == {'aws_access_key_id', 'aws_secret_access_key'}
         and config.get('default', 'aws_access_key_id', fallback='')
         and config.get('default', 'aws_secret_access_key', fallback='')
         and not config.get('default', 'aws_session_token', fallback=''), 'TARGET_CREDENTIALS_INVALID')
    ca = read(BINDINGS / 'config/tls/ca.pem', 16384)
    need(sha(ca) == CA_SHA, 'TARGET_CA_CHANGED')
    probe = base64.b64decode(CLASS_B64, validate=True)
    need(sha(probe) == CLASS_SHA, 'PROBE_CLASS_MISMATCH')
    work = Path(tempfile.mkdtemp(prefix='udp-client-probe-', dir=ROOT))
    key = 'diagnostics/seaweedfs-client/' + str(uuid.uuid4())
    name = 'ouf-udp-s3-probe-' + uuid.uuid4().hex[:12]
    report.update(privateEvidenceDirectory=str(work), diagnosticObjectKey=key, temporaryContainerName=name,
                  bucket=BUCKET, endpoint=ENDPOINT, udpImage=IMAGE, installedSdkVersion='2.54.17',
                  payloadBytes=len(PAYLOAD), payloadSha256=sha(PAYLOAD),
                  sourceNetwork=sorted(app['NetworkSettings']['Networks']), clientNetwork=NETWORK,
                  sameInstalledFactoryAndAdapter=True, springStarted=False,
                  applicationDatabaseTouched=False, applicationBindingsChanged=False,
                  credentialValuesEmitted=False, sourceS3Requests=0)
    try:
        for filename, raw in {'credentials': credentials, 'ca.pem': ca, 'input.csv': PAYLOAD,
                              'UdpStorageClientProbe.class': probe, 'loader.properties': b'',
                              'aws-config': b''}.items():
            path = work / filename
            path.write_bytes(raw)
            os.chmod(path, 0o400)
            os.chown(path, 10004, 10004)
        os.chown(work, 10004, 10004)
        os.chmod(work, 0o500)
        cid = docker('create', '--name', name, '--network', NETWORK, '--pull=never', '--restart=no',
                     '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--user', '10004:10004', '--memory=512m', '--cpus=1', '--pids-limit=128',
                     '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777',
                     '--mount', 'type=bind,src=' + str(work) + ',dst=/probe,readonly',
                     '--env', 'AWS_SHARED_CREDENTIALS_FILE=/probe/credentials', '--env', 'AWS_PROFILE=default',
                     '--env', 'AWS_CONFIG_FILE=/probe/aws-config', '--env', 'AWS_EC2_METADATA_DISABLED=true',
                     '--entrypoint', '/bin/sh', IMAGE, '-c', 'sleep 260').stdout.decode().strip()
        need(re.fullmatch('[a-f0-9]{64}', cid), 'CREATED_CONTAINER_ID_INVALID')
        docker('start', cid)
        report['temporaryContainerStarted'] = True
        report['phase'] = 'JAVA_TLS_IMPORT'
        docker('exec', cid, 'keytool', '-importcert', '-noprompt', '-alias', 'ouf-probe',
               '-file', '/probe/ca.pem', '-keystore', '/tmp/probe.p12', '-storetype', 'PKCS12', '-storepass', 'changeit')
        report['phase'] = 'JAVA_PREFLIGHT'
        report['javaPreflight'] = java(cid, launcher, 'check', key)
        need(report['javaPreflight'].get('status') == 'JAVA_CLIENT_READY'
             and report['javaPreflight'].get('exitCode') == 0, 'JAVA_PREFLIGHT_FAILED')
        intent = {'bucket': BUCKET, 'key': key, 'payloadSha256': sha(PAYLOAD),
                  'maximumLogicalPutCalls': 1, 'sdkDefaultRetriesRetained': True}
        (work / 'request-intent.json').write_text(json.dumps(intent) + '\n')
        os.chmod(work / 'request-intent.json', 0o600)
        report['phase'] = 'JAVA_PUT_HEAD_GET'
        report['diagnosticObjectMayExist'] = True
        report['javaTransfer'] = java(cid, launcher, 'run', key)
        need(report['javaTransfer'].get('status') == 'PUT_HEAD_GET_MATCH'
             and report['javaTransfer'].get('exitCode') == 0, 'JAVA_TRANSFER_NOT_VERIFIED')
        report['phase'] = 'COMPLETE'
        report['status'] = 'UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH'
    finally:
        try:
            cleanup = subprocess.run((*DOCKER, 'rm', '-f', name), capture_output=True, timeout=20)
            report['temporaryContainerRemoved'] = cleanup.returncode == 0
        except subprocess.TimeoutExpired:
            report['temporaryContainerRemoved'] = False
        finally:
            (work / 'credentials').unlink(missing_ok=True)
            report['temporaryCredentialCopyRemoved'] = True
        try:
            current = inspect(CID)
            report['originalApplicationStillRunningUnchangedImage'] = current['State']['Running'] and (
                current['Id'], current['Image'], current['State']['StartedAt']) == identity
        except Exception:
            report['originalApplicationStillRunningUnchangedImage'] = None
    need(report['temporaryContainerRemoved'], 'TEMPORARY_CONTAINER_CLEANUP_FAILED')


if __name__ == '__main__':
    report = {'schema': 'ouf.udp-installed-seaweedfs-client-probe.v1', 'status': 'INCOMPLETE',
              'phase': 'PREPARE', 'diagnosticObjectMayExist': False,
              'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        run(report)
    except Exception as exc:
        report['status'] = 'INCOMPLETE'
        report['reason'] = str(exc) if str(exc) in SAFE_CODES else type(exc).__name__
    report['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if 'privateEvidenceDirectory' in report:
        evidence = Path(report['privateEvidenceDirectory']) / 'result.json'
        evidence.write_text(json.dumps(report, sort_keys=True) + '\n')
        os.chmod(evidence, 0o600)
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['status'] == 'UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH' else 1)

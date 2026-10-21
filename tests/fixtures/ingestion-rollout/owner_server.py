"""Disposable GET-only Owner protocol fixture, not the Onboarding application.

The real Onboarding/IAM provider remain G3 target gates. This server exposes only
the two retained read contracts and checks the exact fixture bearer in memory.
"""
import hmac
import http.server
import json
from pathlib import Path
import sys
DATA=Path(sys.argv[1])
class Owner(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        value=json.loads(DATA.read_bytes());active=value['active'];body=None
        if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+value['bearer']):
            self.send_error(401);return
        root='/api/trusted-human/v1/installations/'+active['installationId']
        if self.path==root+'/active':body={k:v for k,v in active.items()if k!='etag'}
        elif self.path==root+'/revisions/'+str(active['revision']):
            body={'installationId':active['installationId'],'revision':active['revision'],'checksum':active['checksum'],
                  'validationState':'VALIDATED','validationFindings':[],'payload':value['payload']}
        if body is None:self.send_error(404);return
        raw=json.dumps(body,separators=(',',':'),sort_keys=True).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        if self.path.endswith('/active'):self.send_header('ETag',active['etag'])
        self.end_headers();self.wfile.write(raw)
    def log_message(self,*args):pass
http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[2])),Owner).serve_forever()

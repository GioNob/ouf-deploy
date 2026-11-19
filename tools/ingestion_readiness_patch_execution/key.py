"""Typed no-key slot: this patch cannot create or read key material."""
from tools.ingestion_readiness_patch_execution import contract as c
class NativeKey:
    def __init__(self,action,journal,review,human):
        self.action,self.journal,self.human=action,journal,human;self.scope=c.scope(review)
    def create(self):raise c.Denied('PATCH_SECRET_CREATION_FORBIDDEN')
    def observe(self):raise c.Denied('PATCH_SECRET_CREATION_FORBIDDEN')
    def read_for_gateway(self):raise c.Denied('PATCH_GATEWAY_KEY_READ_FORBIDDEN')

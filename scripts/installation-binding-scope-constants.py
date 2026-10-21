"""Change only the two HUMAN scope constants; retain every function and guard."""
import ast,copy
BASE=['openid','authorization.policy.admin','mcp.connect','authorization.permissions.read','authorization.permissions.propose','authorization.proposal.read']
PREVIOUS=BASE+['udp.materialization.retry']
ADDITIONS=['installation.configuration.read','installation.configuration.write','installation.configuration.activate','installation.configuration.export']
REQUESTED=PREVIOUS+ADDITIONS

def require(value,code):
 if not value:raise ValueError(code)
def transform(raw):
 tree=ast.parse(raw);state={};last={}
 allowed=(ast.Expression,ast.Constant,ast.List,ast.Tuple,ast.Dict,ast.Name,ast.Load,ast.BinOp,ast.Add,ast.Subscript)
 for index,node in enumerate(tree.body):
  if not isinstance(node,ast.Assign)or len(node.targets)!=1:continue
  target=node.targets[0]
  if not isinstance(target,ast.Name)or target.id not in('LEGACY_SCOPES','SCOPES','PROFILE'):continue
  require(all(isinstance(n,allowed)for n in ast.walk(ast.Expression(node.value))),'CLOSED_HUMAN_SCOPE_CONSTANT_EXPRESSION_REQUIRED')
  state[target.id]=eval(compile(ast.Expression(node.value),'<literal-human-scope-constant>','eval'),{'__builtins__':{}},state)
  if target.id in('LEGACY_SCOPES','SCOPES'):last[target.id]=index
 require(state.get('LEGACY_SCOPES')==BASE and state.get('SCOPES')==PREVIOUS and set(last)=={'LEGACY_SCOPES','SCOPES'}
  and state['PROFILE']['id']=='ouf.chatbot-human-session.finite-test.v2'and state['PROFILE']['maximumAttempts']==256
  and state['PROFILE']['maximumElapsedSeconds']==7200,'EXACT_RETAINED_SEVEN_SCOPE_FINITE256_HUMAN_REQUIRED')
 guards=[n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget']
 require(len(guards)==1 and any(isinstance(n,ast.Constant)and n.value=='ouf.human-explicit-capability-scope-review.v4'for n in ast.walk(guards[0])),
  'RETAINED_V4_SCOPE_REVIEW_GUARD_REQUIRED')
 changed=copy.deepcopy(tree)
 for name,value in(('LEGACY_SCOPES',PREVIOUS),('SCOPES',REQUESTED)):
  changed.body[last[name]].value=ast.parse(repr(value),mode='eval').body
 strip=lambda t:ast.dump(ast.Module(body=[n for i,n in enumerate(t.body)if i not in set(last.values())],type_ignores=[]),include_attributes=False)
 require(strip(tree)==strip(changed),'ONLY_TWO_LITERAL_SCOPE_CONSTANT_CHANGES_REQUIRED')
 result=(ast.unparse(changed)+'\n').encode();parsed=ast.parse(result)
 require(strip(tree)==strip(parsed),'ALL_HUMAN_FUNCTIONS_AND_GUARDS_MUST_REMAIN_UNCHANGED')
 return result

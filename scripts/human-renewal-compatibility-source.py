"""One explicit review-schema addition to the exact frozen HUMAN validator."""
import ast,hashlib
ORIGINAL_SHA256='2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285'
REVIEW_SCHEMA='ouf.mcp-read-transport-human-reauthentication-review.v1'
ORIGINAL_CLOSURE='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
ADDITION="""review.get('schema') == 'ouf.mcp-read-transport-human-reauthentication-review.v1' and review.get('purpose') == 'CONFIGURATION_AND_VALIDATION' and review.get('predecessorMaximumCumulativeOAuthAttempts') == 256 and type(review.get('priorOAuthAttempts')) is int and review['priorOAuthAttempts'] == 217 and review.get('maximumCumulativeOAuthAttempts') == 256 and review.get('maximumRemainingOAuthAttempts') == 39 and review.get('newWindowSeconds') == 7200 and review.get('freshIssuerAuthenticationRequired') is True and review.get('failedRefreshReplayAllowed') is False and review.get('oldCredentialsReusable') is False and review.get('automaticRenewalAllowed') is False and review.get('budgetReset') is False and review.get('identityAndScopesUnchanged') is True and review.get('requestedScopes') == SCOPES and binding.get('scopes') == SCOPES and review.get('operationBinding', {}).get('sourceClosureHash') == '2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76' and review.get('followup', {}).get('profile') == 'ouf.mcp-ingestion-read-transport-update.v1' and review.get('followup', {}).get('candidateSourceCommit') == '1f2c28d7abadae78680b040ba7b58be62ef85ee9' and review.get('followup', {}).get('separateNativeApprovalRequired') is True and review.get('followup', {}).get('migrationAllowed') is False and review.get('followup', {}).get('gatewayWritesAllowed') is False and review.get('followup', {}).get('grantChangesAllowed') is False and review.get('followup', {}).get('sourceActivationAllowed') is False and review.get('followup', {}).get('jobDispatchAllowed') is False"""
def require(ok,reason):
 if not ok:raise ValueError(reason)
def target(tree):
 classes=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession']
 require(len(classes)==1,'EXACT_ONE_FROZEN_HUMAN_CLASS_REQUIRED')
 methods=[n for n in classes[0].body if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget']
 require(len(methods)==1,'EXACT_ONE_FROZEN_HUMAN_GUARD_REQUIRED')
 calls=[n for n in ast.walk(methods[0])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='require'
  and len(n.args)==2 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED']
 require(len(calls)==1,'EXACT_ONE_FROZEN_RENEWAL_REQUIRE_REQUIRED')
 condition=calls[0].args[0]
 require(isinstance(condition,ast.BoolOp)and isinstance(condition.op,ast.And)and len(condition.values)>=8
  and isinstance(condition.values[0],ast.BoolOp)and isinstance(condition.values[0].op,ast.Or),
  'EXACT_FROZEN_SCHEMA_DISJUNCTION_REQUIRED')
 return calls[0]
def transform(raw):
 require(type(raw)is bytes and 0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==ORIGINAL_SHA256,
  'EXACT_AUTHENTICATED_FROZEN_HUMAN_SOURCE_REQUIRED')
 before=ast.parse(ast.unparse(ast.parse(raw)));after=ast.parse(ast.unparse(before));original=target(before);changed=target(after)
 changed.args[0].values[0].values.append(ast.parse(ADDITION,mode='eval').body)
 # Removing only the new OR term must reconstruct the WHOLE original AST.
 proof=ast.parse(ast.unparse(ast.fix_missing_locations(after)))
 guard=target(proof);first=guard.args[0].values[0]
 require(isinstance(first,ast.BoolOp)and isinstance(first.op,ast.Or)and len(first.values)>=3
  and ast.dump(first.values[-1],include_attributes=False)==ast.dump(ast.parse(ADDITION,mode='eval').body,include_attributes=False),
  'EXACT_ONE_SCHEMA_BRANCH_ADDITION_REQUIRED')
 first.values.pop()
 require(ast.dump(proof,include_attributes=False)==ast.dump(before,include_attributes=False),
  'FROZEN_HUMAN_GUARD_OR_OTHER_CODE_CHANGED')
 result=(ast.unparse(ast.fix_missing_locations(after))+'\n').encode()
 require(0<len(result)<=262144,'BOUNDED_COMPATIBLE_HUMAN_SOURCE_REQUIRED');compile(result,'<sealed-compatible-human-session>','exec')
 return result

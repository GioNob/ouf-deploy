"""Pure governed bootstrap delta. No Docker, credentials, DB, authority or effects."""
import copy

FLAGS=('--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY')

def require(ok,code):
    if not ok:raise ValueError(code)

def compile_config(config):
    require(type(config)is dict and config.get('Entrypoint')==['java','-jar','/app/app.jar'],
            'EXACT_JAVA_JAR_ENTRYPOINT_REQUIRED')
    command=config.get('Cmd') or []
    require(type(command)is list and len(command)<=64 and all(type(v)is str and 0<len(v)<=4096 for v in command),
            'BOUNDED_APPLICATION_COMMAND_REQUIRED')
    for value in command:
        key=value.split('=',1)[0].lower().replace('-','').replace('.','').replace('_','')
        require(value!='--' and not key.startswith(('springflyway','oufingestionstartupschemamode')),
                'STARTUP_POLICY_ARGUMENT_COLLISION')
    environment={}
    for item in config.get('Env',[]):
        key,separator,value=item.partition('=')
        require(separator and key and key not in environment,'UNIQUE_BOOTSTRAP_ENVIRONMENT_REQUIRED')
        environment[key]=value
    require('SPRING_FLYWAY_ENABLED' not in environment or environment['SPRING_FLYWAY_ENABLED']=='false',
            'STARTUP_POLICY_ENVIRONMENT_COLLISION')
    after=copy.deepcopy(config)
    after['Env']=[*config.get('Env',[])]
    if 'SPRING_FLYWAY_ENABLED' not in environment:after['Env'].append('SPRING_FLYWAY_ENABLED=false')
    after['Cmd']=[*command,*FLAGS]
    return after

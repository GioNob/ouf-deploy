import copy,hashlib,http.client,io,json,os,re,signal,socket,stat,sys,tempfile,types

from pathlib import Path

frames=types.ModuleType('frames')

exec(compile('"""Complete local Docker frame templates; no effects, secrets or runtime authority."""\nimport copy\nimport ipaddress\nimport re\n\nNO_RESTART={\'Name\':\'no\',\'MaximumRetryCount\':0}\nCONFIG_DESTINATION=\'/usr/local/apisix/conf/config.yaml\'\nOWNER_ENV=\'OUF_INGESTION_READ_OWNER_KEY\'\nSECRET_SLOT=\'@ouf-secret-reference:ingestionReadOwnerKey\'\n\ndef require(ok,code):\n    if not ok:raise ValueError(code)\n\ndef environment(entries):\n    require(type(entries)is list and len(entries)<=256,\'BOUNDED_ENVIRONMENT_REQUIRED\')\n    result={}\n    for row in entries:\n        require(type(row)is str and \'=\'in row and len(row)<=65536,\'BOUNDED_ENVIRONMENT_ENTRY_REQUIRED\')\n        key,value=row.split(\'=\',1)\n        require(re.fullmatch(\'[A-Za-z_][A-Za-z_0-9]*\',key)and key not in result and \'\\0\'not in value,\'UNIQUE_ENVIRONMENT_REQUIRED\')\n        result[key]=value\n    return result\n\ndef expose_owner_environment(raw):\n    require(type(raw)is bytes and 0<len(raw)<=1048576,\'BOUNDED_GATEWAY_CONFIG_REQUIRED\')\n    marker=\'nginx_config:\\n  envs:\\n\';text=raw.decode(\'utf-8\')\n    require(text.count(marker)==1,\'EXACT_NGINX_ENV_ALLOWLIST_REQUIRED\')\n    head,tail=text.split(marker,1);names=[]\n    for line in tail.splitlines(keepends=True):\n        match=re.fullmatch(r\'  - ([A-Z][A-Z0-9_]{0,127})\\n\',line)\n        if not match:break\n        names.append(match[1])\n    require(names and len(names)==len(set(names)),\'CLOSED_NGINX_ENV_ALLOWLIST_REQUIRED\')\n    # Reject another spelling elsewhere: do not mistake an unrelated YAML key\n    # or duplicate list for an already exposed worker environment binding.\n    require(text.count(OWNER_ENV)==names.count(OWNER_ENV),\'UNAMBIGUOUS_OWNER_ENV_ALLOWLIST_REQUIRED\')\n    return raw if OWNER_ENV in names else (head+marker+\'  - \'+OWNER_ENV+\'\\n\'+tail).encode()\n\ndef replace_config_bind(host,old_source,new_source):\n    changed=0\n    for i,value in enumerate(host.get(\'Binds\')or[]):\n        if value.startswith(old_source+\':\'+CONFIG_DESTINATION+\':\'):\n            require(value.split(\':\',2)[2].split(\',\')[0]==\'ro\',\'READ_ONLY_GATEWAY_CONFIG_REQUIRED\')\n            host[\'Binds\'][i]=new_source+value[len(old_source):];changed+=1\n    for row in host.get(\'Mounts\')or[]:\n        if row.get(\'Target\')==CONFIG_DESTINATION:\n            require(row.get(\'Type\')==\'bind\'and row.get(\'Source\')==old_source and row.get(\'ReadOnly\')is True,\n                    \'EXACT_READ_ONLY_GATEWAY_CONFIG_REQUIRED\')\n            row[\'Source\']=new_source;changed+=1\n    require(changed==1,\'EXACT_ONE_CONFIG_BIND_REPLACEMENT_REQUIRED\')\n\ndef endpoints(actual):\n    observed=actual[\'NetworkSettings\'][\'Networks\']\n    require(type(observed)is dict and 1<=len(observed)<=8,\'EXPLICIT_RETAINED_NETWORKS_REQUIRED\')\n    result={}\n    for name,row in observed.items():\n        require(re.fullmatch(\'[A-Za-z0-9_.-]{1,128}\',name)and re.fullmatch(\'[0-9a-f]{64}\',row[\'NetworkID\']),\n                \'EXACT_NETWORK_IDENTITY_REQUIRED\')\n        require(not row.get(\'Links\'),\'LINKED_NETWORK_REQUIRES_DISTINCT_REVIEW\')\n        aliases=row.get(\'Aliases\')or[]\n        require(type(aliases)is list and len(aliases)<=32 and all(type(v)is str and re.fullmatch(\'[A-Za-z0-9_.-]{1,253}\',v)for v in aliases),\n                \'EXPLICIT_NETWORK_ALIASES_REQUIRED\')\n        ipam=copy.deepcopy(row.get(\'IPAMConfig\')or{})\n        for field,source,version in [(\'IPv4Address\',\'IPAddress\',4),(\'IPv6Address\',\'GlobalIPv6Address\',6)]:\n            value=row.get(source)\n            if value:\n                require(ipaddress.ip_address(value).version==version,\'EXACT_OBSERVED_ENDPOINT_ADDRESS_REQUIRED\')\n                require(not ipam.get(field)or ipam[field]==value,\'OBSERVED_AND_REQUESTED_IPAM_DRIFT\')\n                ipam[field]=value\n        mac=row.get(\'MacAddress\')or\'\'\n        require(re.fullmatch(\'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\',mac),\'EXACT_OBSERVED_ENDPOINT_MAC_REQUIRED\')\n        result[name]={\'NetworkID\':row[\'NetworkID\'],\'Aliases\':[v for v in aliases if v not in(actual[\'Id\'],actual[\'Id\'][:12])],\n                      \'IPAMConfig\':ipam,\'MacAddress\':mac}\n        if row.get(\'DriverOpts\')is not None:result[name][\'DriverOpts\']=copy.deepcopy(row[\'DriverOpts\'])\n        if \'GwPriority\'in row:result[name][\'GwPriority\']=row[\'GwPriority\']\n    return result\n\ndef frame(module,actual,image_id,candidate_config,draft,new_gateway_config_path=None):\n    # The caller binds actual to its approved installation/runtime profile.\n    # Network IDs, names, addresses and MACs below are parameters, never defaults.\n    require(module in(\'ingestion\',\'gateway\')and re.fullmatch(\'sha256:[0-9a-f]{64}\',image_id),\'EXACT_TWO_MODULE_FRAME_REQUIRED\')\n    config=copy.deepcopy(actual[\'Config\']);host=copy.deepcopy(actual[\'HostConfig\'])\n    require(host.get(\'AutoRemove\')is not True and host.get(\'Privileged\')is not True\n            and not host.get(\'Links\')and not host.get(\'VolumesFrom\')and not host.get(\'ContainerIDFile\')\n            and not str(host.get(\'PidMode\',\'\')).startswith(\'container:\')and not str(host.get(\'IpcMode\',\'\')).startswith(\'container:\'),\n            \'INDEPENDENT_RETAINABLE_CONTAINER_REQUIRED\')\n    restart=copy.deepcopy(host[\'RestartPolicy\'])\n    require(restart in(NO_RESTART,{\'Name\':\'unless-stopped\',\'MaximumRetryCount\':0}),\'REVIEWED_RESTART_POLICY_REQUIRED\')\n    if \'OomKillDisable\'in host:\n        require(host[\'OomKillDisable\']is None or type(host[\'OomKillDisable\'])is bool,\'EXACT_OOM_POLICY_REQUIRED\')\n    host[\'RestartPolicy\']=copy.deepcopy(NO_RESTART)\n    values=environment(config.get(\'Env\')or[])\n    retained_endpoints=endpoints(actual)\n    legacy_mac=config.pop(\'MacAddress\',None)\n    require(legacy_mac in(None,\'\') or type(legacy_mac)is str and re.fullmatch(\'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\',legacy_mac)\n            and legacy_mac.lower()in{row[\'MacAddress\'].lower()for row in retained_endpoints.values()},\n            \'LEGACY_CONTAINER_MAC_MUST_MATCH_OBSERVED_ENDPOINT\')\n    if module==\'ingestion\':\n        require(config.get(\'User\')==candidate_config.get(\'User\')==\'10002:10002\'\n                and config.get(\'Entrypoint\')==candidate_config.get(\'Entrypoint\')==[\'java\',\'-jar\',\'/app/app.jar\']\n                and config.get(\'WorkingDir\')==candidate_config.get(\'WorkingDir\'), \'EXACT_RETAINED_JAVA_PROCESS_CONTRACT_REQUIRED\')\n        proposed=draft[\'ingestion\']\n        for key,value in {**proposed[\'ownerReadEnvironmentAdditions\'],**proposed[\'startupEnvironmentAddition\']}.items():\n            require(key not in values or values[key]==value,\'OWNER_STARTUP_ENVIRONMENT_COLLISION\')\n            values[key]=value\n        require(proposed[\'bootstrapCmd\'][-2:]==[\'--spring.flyway.enabled=false\',\'--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY\'],\n                \'QUALIFIED_VALIDATE_ONLY_BOOTSTRAP_REQUIRED\')\n        config[\'Cmd\']=copy.deepcopy(proposed[\'bootstrapCmd\'])\n        config[\'Labels\']={**(config.get(\'Labels\')or{}),\'org.opencontainers.image.revision\':draft[\'candidate\'][\'sourceCommit\']}\n        new=proposed[\'readOnlyBindAddition\']\n        require(new[\'Type\']==\'bind\'and new[\'RW\']is False and all(m[\'Destination\']!=new[\'Destination\']for m in actual[\'Mounts\']),\n                \'ONE_NEW_READ_ONLY_OWNER_BIND_REQUIRED\')\n        host.setdefault(\'Binds\',[])\n        if host[\'Binds\']is None:host[\'Binds\']=[]\n        host[\'Binds\'].append(new[\'Source\']+\':\'+new[\'Destination\']+\':ro\')\n        inherited=environment(candidate_config.get(\'Env\')or[])\n        home=inherited.get(\'JAVA_HOME\')\n        require(not home or home.rstrip(\'/\')+\'/bin\'in values.get(\'PATH\',inherited.get(\'PATH\',\'\')).split(\':\'),\n                \'PACKAGED_JAVA_SEARCH_PATH_REQUIRES_REVIEW\')\n        require(set((candidate_config.get(\'Volumes\')or{}))<={m[\'Destination\']for m in actual[\'Mounts\']},\n                \'NO_NEW_UNREVIEWED_IMAGE_VOLUME_REQUIRED\')\n    else:\n        require(image_id==actual[\'Image\']and OWNER_ENV not in values,\'EXACT_UNCHANGED_GATEWAY_IMAGE_REQUIRED\')\n        values[OWNER_ENV]=SECRET_SLOT\n        if new_gateway_config_path:\n            selected=[m for m in actual[\'Mounts\']if m[\'Destination\']==CONFIG_DESTINATION]\n            require(len(selected)==1 and selected[0][\'Type\']==\'bind\'and selected[0][\'RW\']is False,\'EXACT_CONFIG_BIND_REQUIRED\')\n            replace_config_bind(host,selected[0][\'Source\'],new_gateway_config_path)\n    config[\'Env\']=[key+\'=\'+value for key,value in sorted(values.items())]\n    config[\'Image\']=image_id\n    if config.get(\'Hostname\')==actual[\'Id\'][:12]:config[\'Hostname\']=\'\'\n    require(not config.get(\'Healthcheck\')or module==\'gateway\'or config[\'Healthcheck\']==candidate_config.get(\'Healthcheck\'),\n            \'REVIEWED_EXISTING_HEALTHCHECK_REQUIRED\')\n    return {\'schema\':\'ouf.ingestion-local-docker-frame-template.v1\',\'module\':module,\'name\':actual[\'Name\'].lstrip(\'/\'),\n        \'requestTemplate\':{**config,\'HostConfig\':host,\'NetworkingConfig\':{\'EndpointsConfig\':retained_endpoints}},\n        \'restoreRestartPolicy\':restart,\'oldMounts\':copy.deepcopy(actual[\'Mounts\']),\n        \'preserveObservedAddressesAndMacs\':True,\'resolveGatewaySecretAfterNativeAuthorityRequired\':module==\'gateway\',\n        \'legacyContainerMacMovedToExplicitEndpoints\':bool(legacy_mac),\n        \'nativeCreationRoundTripQualified\':False,\n        \'runtimeAuthorityIssued\':False,\'targetApplyAuthorized\':False}\n',"<sealed-frames>","exec"),frames.__dict__)

package=types.ModuleType('package')

exec(compile('"""Authenticate the retained scanned ZIP without extraction or target effects."""\nimport hashlib\nimport io\nimport json\nimport re\nimport stat\nimport zipfile\nfrom pathlib import PurePosixPath\n\nSOURCE=\'0fe0de60c6d980fe97610acf195d4bfd46d3777f\'\nIMAGE=\'sha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b\'\nZIP_SHA=\'02974a024e66d2f3adb9933f654954868598f6dfcec8899bf76daced9a1aeb02\'\nZIP_BYTES=352127312\nLOCK_SHA=\'5f9b0af870f123ca804d4ac0e63613728c13bcff75b590235464e4e49c5a8a83\'\nLIMIT=2147483648\n\ndef require(ok,code):\n    if not ok:raise ValueError(code)\n\ndef sha(raw):return hashlib.sha256(raw).hexdigest()\n\ndef hashed(stream,maximum):\n    h=hashlib.sha256();size=0\n    for block in iter(lambda:stream.read(1048576),b\'\'):\n        size+=len(block);require(size<=maximum,\'BOUNDED_PACKAGE_BYTES_REQUIRED\');h.update(block)\n    return h.hexdigest(),size\n\ndef parsed(raw):\n    def unique(rows):\n        result={}\n        for k,v in rows:\n            require(k not in result,\'UNIQUE_PACKAGE_JSON_KEYS_REQUIRED\');result[k]=v\n        return result\n    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,\'FINITE_PACKAGE_JSON_REQUIRED\'))\n\ndef inventory(stream,expected_sha=ZIP_SHA,expected_bytes=ZIP_BYTES):\n    stream.seek(0);require(hashed(stream,LIMIT)==(expected_sha,expected_bytes),\'EXACT_SCANNED_ZIP_REQUIRED\');stream.seek(0)\n    with zipfile.ZipFile(stream)as z:\n        rows=z.infolist();require(1<=len(rows)<=128,\'BOUNDED_PACKAGE_INDEX_REQUIRED\');files={};total=0\n        for row in rows:\n            p=PurePosixPath(row.filename);mode=row.external_attr>>16\n            require(not p.is_absolute()and \'..\'not in p.parts and str(p)==row.filename\n                    and not row.is_dir()and row.filename not in files and not row.flag_bits&1\n                    and stat.S_IFMT(mode)in(0,stat.S_IFREG)and 0<row.file_size<=LIMIT,\'SAFE_UNIQUE_PACKAGE_MEMBERS_REQUIRED\')\n            total+=row.file_size;require(total<=LIMIT,\'BOUNDED_EXPANDED_PACKAGE_REQUIRED\');files[row.filename]=row\n        require(\'SHA256SUMS\'in files and files[\'SHA256SUMS\'].file_size<=32768,\'BOUNDED_PACKAGE_CHECKSUMS_REQUIRED\')\n        checks={}\n        for line in z.read(files[\'SHA256SUMS\']).decode(\'ascii\').splitlines():\n            match=re.fullmatch(r\'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)\',line)\n            require(match and match[2]not in checks,\'EXACT_UNIQUE_PACKAGE_CHECKSUMS_REQUIRED\');checks[match[2]]=match[1]\n        require(set(checks)==set(files)-{\'SHA256SUMS\'},\'COMPLETE_PACKAGE_CHECKSUM_SET_REQUIRED\')\n        for name,wanted in checks.items():\n            with z.open(files[name])as f:require(hashed(f,LIMIT)==(wanted,files[name].file_size),\'PACKAGE_MEMBER_DIGEST_DRIFT\')\n        needed={\'image.docker.tar\',\'application.jar\',\'candidate-manifest.json\',\'package-record.json\',\'trivy-image.json\',\'source-inventory.json\'}\n        require(needed<=set(files),\'COMPLETE_SCANNED_PACKAGE_REQUIRED\')\n        require(all(files[n].file_size<=16777216 for n in needed-{\'image.docker.tar\',\'application.jar\'}),\'BOUNDED_PACKAGE_METADATA_REQUIRED\')\n        manifest=parsed(z.read(files[\'candidate-manifest.json\']))\n        require(manifest.get(\'sourceCommit\')==SOURCE and manifest.get(\'imageId\')==IMAGE\n                and manifest.get(\'sourceLockSha256\')==LOCK_SHA and manifest.get(\'module\')==\'ingestion\'\n                and manifest.get(\'repository\')==\'GioNob/ouf-ingestion-runtime\'\n                and manifest.get(\'scanGate\')==\'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED\'\n                and manifest.get(\'runtimeAuthorityIssued\')is False and manifest.get(\'targetApplyAuthorized\')is False,\n                \'EXACT_QUALIFIED_PACKAGE_PROVENANCE_REQUIRED\')\n        record=parsed(z.read(files[\'package-record.json\']))\n        require(record.get(\'sourceCommit\')==SOURCE and record.get(\'imageId\')==IMAGE and record.get(\'module\')==\'ingestion\',\n                \'EXACT_PACKAGE_IMAGE_RECORD_REQUIRED\')\n        scan=parsed(z.read(files[\'trivy-image.json\']))\n        require(scan.get(\'SchemaVersion\')==2 and scan.get(\'Metadata\',{}).get(\'ImageID\')==IMAGE\n                and type(scan.get(\'Results\'))is list,\'SCANNED_IMAGE_REPORT_BINDING_REQUIRED\')\n        coverage={(r.get(\'Class\'),r.get(\'Type\'))for r in scan[\'Results\']}\n        require((\'lang-pkgs\',\'jar\')in coverage and any(c==\'os-pkgs\'for c,_ in coverage),\'SCANNER_COVERAGE_REQUIRED\')\n        for row in scan[\'Results\']:\n            require(row.get(\'Class\')in(\'os-pkgs\',\'lang-pkgs\')and type(row.get(\'Vulnerabilities\',[]))is list,\'CLOSED_SCANNER_REPORT_REQUIRED\')\n            for finding in row.get(\'Vulnerabilities\',[]):\n                require(finding.get(\'Severity\')in(\'LOW\',\'MEDIUM\'),\'HIGH_CRITICAL_UNKNOWN_SCAN_GATE_BLOCKED\')\n        return {\'schema\':\'ouf.ingestion-scanned-package-custody.v1\',\'zipSha256\':expected_sha,\'zipBytes\':expected_bytes,\n                \'files\':{n:{\'sha256\':checks[n],\'bytes\':files[n].file_size}for n in checks},\n                \'sourceCommit\':SOURCE,\'imageId\':IMAGE,\'sourceLockSha256\':LOCK_SHA,\'scanGate\':manifest[\'scanGate\'],\n                \'runtimeAuthorityIssued\':False,\'targetApplyAuthorized\':False}\n\ndef copy_member(stream,name,output,proof):\n    require(name in proof[\'files\'],\'EXACT_AUTHENTICATED_PACKAGE_MEMBER_REQUIRED\')\n    stream.seek(0);h=hashlib.sha256();size=0\n    with zipfile.ZipFile(stream)as z,z.open(name)as f:\n        for block in iter(lambda:f.read(1048576),b\'\'):\n            size+=len(block);require(size<=proof[\'files\'][name][\'bytes\'],\'PACKAGE_MEMBER_CHANGED\');h.update(block);output.write(block)\n    require((h.hexdigest(),size)==(proof[\'files\'][name][\'sha256\'],proof[\'files\'][name][\'bytes\']),\'PACKAGE_MEMBER_CHANGED\')\n\ndef jar_proof(raw,sql_manifest):\n    require(type(raw)is bytes and 0<len(raw)<=268435456,\'BOUNDED_APPLICATION_JAR_REQUIRED\')\n    with zipfile.ZipFile(io.BytesIO(raw))as z:\n        rows=z.infolist();require(len(rows)<=20000 and len({r.filename for r in rows})==len(rows),\'UNIQUE_BOUNDED_JAR_REQUIRED\')\n        expected={\'BOOT-INF/classes/db/migration/\'+r[\'script\']:r[\'resourceSha256\']for r in sql_manifest[\'migrations\']}\n        selected={r.filename:r for r in rows if r.filename.startswith(\'BOOT-INF/classes/db/migration/\')and not r.is_dir()}\n        require(len(expected)==18 and set(selected)==set(expected),\'EXACT18_UNCHANGED_MIGRATION_SET_REQUIRED\')\n        for name,wanted in expected.items():\n            row=selected[name];require(not row.flag_bits&1 and 0<row.file_size<=1048576 and sha(z.read(row))==wanted,\n                                       \'EXACT18_UNCHANGED_MIGRATION_BYTES_REQUIRED\')\n        require(any(r.filename.endswith(\'/IngestionValidateOnlyStartup.class\')for r in rows),\'QUALIFIED_STARTUP_GUARD_CLASS_REQUIRED\')\n    return {\'jarSha256\':sha(raw),\'migrationCount\':18,\'sqlBytesUnchanged\':True,\'runtimeAuthorityIssued\':False}\n',"<sealed-package>","exec"),package.__dict__)

custody=types.ModuleType('custody')

exec(compile('"""Docker archive and realized image byte custody; no effects or authority.\n\nCaller authenticates original publisher/ZIP and file custody separately.\nArchive/file-digest or image-inspection equality never grants installation.\n"""\nimport gzip,hashlib,json,re,tarfile\nfrom pathlib import PurePosixPath\n\nLIMIT=2147483648\nFIELDS=(\'User\',\'Entrypoint\',\'Cmd\',\'Env\',\'WorkingDir\',\'Labels\',\'Volumes\',\'ExposedPorts\',\'StopSignal\',\'Healthcheck\',\'Shell\')\n\nclass ImageCustodyDenied(ValueError):pass\n\ndef require(ok, reason):\n    if not ok:raise ImageCustodyDenied(reason)\n\ndef encoded(value):return json.dumps(value,sort_keys=True,separators=(\',\',\':\'),allow_nan=False).encode()\ndef digest(value):return hashlib.sha256(encoded(value)).hexdigest()\ndef hashed(stream,limit):\n    h=hashlib.sha256();count=0\n    while True:\n        raw=stream.read(min(1048576,limit-count+1))\n        if not raw:break\n        count+=len(raw);require(count<=limit,\'BOUNDED_IMAGE_BYTES_REQUIRED\');h.update(raw)\n    return h.hexdigest(),count\n\ndef parsed(raw):\n    def unique(rows):\n        result={}\n        for k,v in rows:\n            require(k not in result,\'DUPLICATE_IMAGE_METADATA_KEY\');result[k]=v\n        return result\n    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,\'FINITE_IMAGE_METADATA_REQUIRED\'))\n\ndef archive(stream,expected_tar_sha256,expected_image,expected_source):\n    require(re.fullmatch(\'[0-9a-f]{64}\',expected_tar_sha256) is not None\n            and re.fullmatch(\'sha256:[0-9a-f]{64}\',expected_image) is not None\n            and re.fullmatch(\'[0-9a-f]{40}\',expected_source) is not None,\'EXACT_IMAGE_BINDINGS_REQUIRED\')\n    stream.seek(0);require(hashed(stream,LIMIT)[0]==expected_tar_sha256,\'AUTHENTICATED_ARCHIVE_BYTES_CHANGED\');stream.seek(0)\n    with tarfile.open(fileobj=stream,mode=\'r:\') as tar:\n        members={}\n        for row in tar:\n            path=PurePosixPath(row.name)\n            require(not path.is_absolute() and \'..\' not in path.parts and str(path)==row.name\n                    and row.name not in members and len(members)<512,\'SAFE_UNIQUE_IMAGE_ARCHIVE_REQUIRED\')\n            require(row.isfile() or row.isdir(),\'IMAGE_ARCHIVE_LINK_OR_SPECIAL_ENTRY_DENIED\')\n            require(0<=row.size<=LIMIT,\'BOUNDED_IMAGE_MEMBER_REQUIRED\');members[row.name]=row\n        def member(name):\n            require(type(name) is str and name in members and members[name].isfile(),\'EXACT_IMAGE_MEMBER_REQUIRED\')\n            return members[name]\n        def small(name,limit):\n            row=member(name);require(row.size<=limit,\'BOUNDED_IMAGE_METADATA_REQUIRED\')\n            with tar.extractfile(row) as src:return src.read(limit+1)\n        manifest=parsed(small(\'manifest.json\',131072))\n        require(type(manifest) is list and len(manifest)==1 and type(manifest[0]) is dict,\'ONE_IMAGE_ARCHIVE_REQUIRED\')\n        image=manifest[0];raw=small(image[\'Config\'],2097152)\n        require(\'sha256:\'+hashlib.sha256(raw).hexdigest()==expected_image,\'IMAGE_CONFIG_DIGEST_DRIFT\')\n        config=parsed(raw)\n        require(config.get(\'os\')==\'linux\' and config.get(\'architecture\')==\'amd64\',\'EXACT_IMAGE_PLATFORM_REQUIRED\')\n        require(type(config.get(\'config\')) is dict and config[\'config\'].get(\'Labels\',{}).get(\'org.opencontainers.image.revision\')==expected_source,\'IMAGE_SOURCE_LABEL_DRIFT\')\n        layers=image.get(\'Layers\');root=config.get(\'rootfs\',{})\n        require(root.get(\'type\')==\'layers\' and type(layers) is list and 1<=len(layers)<=64\n                and len(layers)==len(set(layers)) and type(root.get(\'diff_ids\')) is list\n                and len(root[\'diff_ids\'])==len(layers),\'EXACT_ROOTFS_LAYER_SET_REQUIRED\')\n        observations=[];total=0\n        for name,expected in zip(layers,root[\'diff_ids\']):\n            row=member(name)\n            with tar.extractfile(row) as src:blob,size=hashed(src,LIMIT)\n            if name.startswith(\'blobs/sha256/\'):\n                require(name==\'blobs/sha256/\'+blob,\'CONTENT_ADDRESSED_LAYER_DRIFT\')\n            with tar.extractfile(row) as src:\n                magic=src.read(2);src.seek(0)\n                if magic==b\'\\x1f\\x8b\':\n                    with gzip.GzipFile(fileobj=src) as expanded:actual,expanded_size=hashed(expanded,LIMIT-total)\n                else:actual,expanded_size=hashed(src,LIMIT-total)\n            total+=expanded_size\n            require(expected==\'sha256:\'+actual,\'ROOTFS_LAYER_BYTES_DRIFT\')\n            observations.append({\'blobSha256\':blob,\'diffId\':expected,\'archiveBytes\':size,\'expandedBytes\':expanded_size})\n        tags=image.get(\'RepoTags\')\n        require(tags is None or type(tags) is list and len(tags)<=16\n                and all(type(x) is str and 0<len(x)<=256 for x in tags),\'BOUNDED_IMAGE_TAGS_REQUIRED\')\n        return {\'schema\':\'ouf.image-archive-byte-custody.v1\',\'imageId\':expected_image,\n                \'sourceCommit\':expected_source,\'archiveSha256\':expected_tar_sha256,\n                \'configSha256\':expected_image[7:],\'configBytes\':len(raw),\'layers\':observations,\'platform\':\'linux/amd64\',\n                \'repositoryTags\':tags or [],\'imageConfig\':config[\'config\'],\n                \'configMember\':image[\'Config\'],\'layerMembers\':layers,\n                \'archiveByteCustodyProven\':True,\'targetApplyAuthorized\':False}\n\ndef manifest_bytes(audit):\n    """Exact Docker schema2 descriptors, with unchanged config/layer bytes."""\n    require(audit.get(\'imageId\')==\'sha256:\'+audit[\'configSha256\']\n            and type(audit.get(\'configBytes\')) is int and 0<audit[\'configBytes\']<=2097152,\n            \'EXACT_CONFIGURATION_BYTE_IDENTITY_REQUIRED\')\n    descriptor=lambda media,digest,size:{\'mediaType\':media,\'digest\':digest,\'size\':size}\n    layers=[]\n    for row in audit[\'layers\']:\n        plain=\'sha256:\'+row[\'blobSha256\']==row[\'diffId\']\n        layers.append(descriptor(\'application/vnd.docker.image.rootfs.diff.tar\'+(\'\' if plain else \'.gzip\'),\n            \'sha256:\'+row[\'blobSha256\'],row[\'archiveBytes\']))\n    value={\'schemaVersion\':2,\'mediaType\':\'application/vnd.docker.distribution.manifest.v2+json\',\n        \'config\':descriptor(\'application/vnd.docker.container.image.v1+json\',audit[\'imageId\'],audit[\'configBytes\']),\n        \'layers\':layers}\n    # Descriptor order matches the image-spec encoding; no native metadata is\n    # normalized or guessed. This exact byte string is included in the archive.\n    return json.dumps(value,separators=(\',\',\':\'),allow_nan=False).encode()\n\ndef native_identity(audit):\n    raw=manifest_bytes(audit)\n    return {\'profile\':\'ouf.config-and-native-manifest-identity.v1\',\n        \'configurationImageId\':audit[\'imageId\'],\'nativeImageId\':\'sha256:\'+hashlib.sha256(raw).hexdigest(),\n        \'manifestBytes\':len(raw),\'platform\':\'linux/amd64\'}\n\ndef runtime_image_id(audit):\n    binding=audit.get(\'nativeIdentity\')\n    if binding is None:return audit[\'imageId\']\n    require(binding==native_identity(audit),\'EXACT_NATIVE_MANIFEST_IDENTITY_REQUIRED\')\n    return binding[\'nativeImageId\']\n\ndef unbound_audit(audit):return {k:v for k,v in audit.items() if k!=\'nativeIdentity\'}\n\ndef tagless_archive(source,output,audit,*,containerd=False):\n    """Re-envelope exact authenticated config/layers without repository tags.\n\n    No image rebuild, new config, layer or publisher signature. Caller reaudits\n    returned archive hash/image/source before import; original provenance is\n    retained separately. Exclude unrelated OCI metadata/old tag descriptors.\n    """\n    source.seek(0);require(hashed(source,LIMIT)[0]==audit[\'archiveSha256\'],\'AUTHENTICATED_ARCHIVE_BYTES_CHANGED\');source.seek(0)\n    output.seek(0);output.truncate()\n    with tarfile.open(fileobj=source,mode=\'r:\') as original,tarfile.open(fileobj=output,mode=\'w\') as target:\n        import io\n        manifest=[{\'Config\':audit[\'configMember\'],\'RepoTags\':None,\'Layers\':audit[\'layerMembers\']}]\n        raw=encoded(manifest);row=tarfile.TarInfo(\'manifest.json\');row.size=len(raw);row.mode=0o600\n        target.addfile(row,io.BytesIO(raw))\n        if containerd:\n            content=manifest_bytes(audit);binding=native_identity(audit)\n            entries={\'oci-layout\':encoded({\'imageLayoutVersion\':\'1.0.0\'}),\n                \'index.json\':encoded({\'schemaVersion\':2,\'manifests\':[{\n                    \'mediaType\':\'application/vnd.docker.distribution.manifest.v2+json\',\n                    \'digest\':binding[\'nativeImageId\'],\'size\':len(content),\n                    \'platform\':{\'architecture\':\'amd64\',\'os\':\'linux\'}}]}),\n                \'blobs/sha256/\'+binding[\'nativeImageId\'][7:]:content}\n            require(not set(entries)&{audit[\'configMember\'],*audit[\'layerMembers\']},\'NATIVE_MANIFEST_MEMBER_COLLISION\')\n            # An explicit OCI index prevents the legacy importer from choosing\n            # alternative compressed layer descriptors from its local cache.\n            for name,body in entries.items():\n                row=tarfile.TarInfo(name);row.size=len(body);row.mode=0o600\n                target.addfile(row,io.BytesIO(body))\n        copies={name:name for name in [audit[\'configMember\'],*audit[\'layerMembers\']]}\n        if containerd:\n            copies[\'blobs/sha256/\'+audit[\'configSha256\']]=audit[\'configMember\']\n            for name,layer in zip(audit[\'layerMembers\'],audit[\'layers\']):\n                copies[\'blobs/sha256/\'+layer[\'blobSha256\']]=name\n        for name,source_name in copies.items():\n            old=original.getmember(source_name);require(old.isfile(),\'EXACT_IMAGE_MEMBER_REQUIRED\')\n            row=tarfile.TarInfo(name);row.size=old.size;row.mode=0o600\n            with original.extractfile(old) as content:target.addfile(row,content)\n    output.flush();output.seek(0);result,size=hashed(output,LIMIT);output.seek(0)\n    return {\'originalArchiveSha256\':audit[\'archiveSha256\'],\'derivedArchiveSha256\':result,\n            \'archiveBytes\':size,\'imageRebuilt\':False,\'newSignatureIssued\':False}\n\ndef loaded(audit,native):\n    expected=runtime_image_id(audit)\n    require(type(native) is dict and native.get(\'Id\')==expected\n            and native.get(\'Os\')==\'linux\' and native.get(\'Architecture\')==\'amd64\',\'NATIVE_IMAGE_IDENTITY_DRIFT\')\n    require(native.get(\'RootFS\')=={\'Type\':\'layers\',\'Layers\':[r[\'diffId\'] for r in audit[\'layers\']]},\'NATIVE_ROOTFS_CUSTODY_DRIFT\')\n    require(type(native.get(\'Config\')) is dict and all(native[\'Config\'].get(k)==audit[\'imageConfig\'].get(k) for k in FIELDS),\'NATIVE_IMAGE_EXECUTION_CONFIG_DRIFT\')\n    return {\'schema\':\'ouf.loaded-image-byte-custody.v1\',\'imageId\':expected,\n            \'sourceCommit\':audit[\'sourceCommit\'],\'archiveSha256\':audit[\'archiveSha256\'],\n            \'rootfsLayerCount\':len(audit[\'layers\']),\'nativeConfigProjectionHash\':digest({k:native[\'Config\'].get(k) for k in FIELDS}),\n            \'nativeRootfsHash\':digest(native[\'RootFS\']),\'imageByteCustodyProven\':True,\n            \'completeContainerOciProven\':False,\'transportClosureProven\':False,\'targetApplyAuthorized\':False}\n\n',"<sealed-custody>","exec"),custody.__dict__)

gateway=types.ModuleType('gateway')

exec(compile('import hashlib,os,stat\nfrom pathlib import Path\nclass Denied(Exception):\n    pass\n\ndef require(ok, code):\n    if not ok:\n        raise Denied(code)\nEXTERNAL_ADMIN_KEY = \'/opt/ouf/secrets/apisix-admin-key\'\n\n_EXISTING_CONFIG_CUSTODY = {\n    # These are the observed, already-running selections on this host. Do not\n    # change ownership of /opt/ouf or the files mounted into live containers.\n    \'/opt/ouf/installation/active-projection.json\': {\n        \'parents\': {\'/opt/ouf\': (1000, 1000, 0o750),\n                    \'/opt/ouf/installation\': (0, 0, 0o700)},\n        \'file\': (0, 0, 0o600)},\n    \'/opt/ouf/secrets/onboarding-ths.yaml\': {\n        \'parents\': {\'/opt/ouf\': (1000, 1000, 0o750),\n                    \'/opt/ouf/secrets\': (1000, 1000, 0o700)},\n        \'file\': (10003, 10003, 0o400)},\n    EXTERNAL_ADMIN_KEY: {\n        \'parents\': {\'/opt/ouf\': (1000, 1000, 0o750),\n                    \'/opt/ouf/secrets\': (1000, 1000, 0o700)},\n        # 0600 does not grant group access. The observed uid/mode are fixed;\n        # the actual gid is pinned by the returned file metadata.\n        \'file\': (1000, None, 0o600)},\n    \'/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml\': {\n        \'parents\': {}, \'file\': (636, 636, 0o400)},\n}\n\ndef selected_directory_custody(info, path, exception):\n    selected = exception[\'parents\'].get(path) if exception else None\n    if selected is not None:\n        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected\n    return info.st_uid == 0 and not info.st_mode & 0o022\n\ndef selected_file_custody(info, exception):\n    selected = exception[\'file\'] if exception else None\n    if selected is not None:\n        uid,gid,mode=selected\n        return info.st_uid==uid and (gid is None or info.st_gid==gid) and stat.S_IMODE(info.st_mode)==mode\n    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o400,0o440,0o444,0o600,0o640,0o644)\n\ndef private_config(path, expected=None):\n    """Read an exact selected file with pinned, no-follow path custody.\n\n    The three existing selections above have different named owners. All\n    other paths, including newly staged APISIX config, retain root custody.\n    """\n    target = Path(path)\n    require(target.is_absolute() and \'..\' not in target.parts, \'EXACT_APISIX_CONFIG_PATH_REQUIRED\')\n    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))\n    fds = []; ancestors = []\n    try:\n        parent = os.open(\'/\', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)\n        current = \'/\'\n        for name in target.parts[1:-1]:\n            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)\n            fds.append(child); info = os.fstat(child)\n            current = os.path.join(current, name)\n            require(selected_directory_custody(info,current,exception),\'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED\')\n            ancestors.append((parent,name,child,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))\n            parent = child\n        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)\n        s = os.fstat(fd)\n        pin = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)\n        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= 1048576\n                and selected_file_custody(s,exception),\n                \'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED\')\n        raw = b\'\'\n        while len(raw) <= 1048576:\n            part = os.read(fd,65536)\n            if not part: break\n            raw += part\n        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd))\n                == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), \'APISIX_CONFIG_READ_DRIFT\')\n        binding = {\'path\': str(target), \'sha256\': hashlib.sha256(raw).hexdigest(), \'metadata\': list(pin(s))}\n        require(expected is None or binding == expected, \'APISIX_SELECTED_CONFIG_CHANGED\')\n        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)\n        for parent,name,child,seal in ancestors:\n            require(seal == identity(os.fstat(child)) == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),\n                    \'APISIX_CONFIG_ANCESTRY_CHANGED\')\n        return raw, binding\n    finally:\n        for fd in reversed(fds): os.close(fd)',"<sealed-gateway>","exec"),gateway.__dict__)

rootfs=types.ModuleType('rootfs')

exec(compile("import tarfile\nfrom pathlib import PurePosixPath\nMAX=268435456\n\ndef require(ok,code):\n if not ok:raise ValueError(code)\n\ndef rootfs_jar(stream,audit):\n stream.seek(0);found=None;count=0\n with tarfile.open(fileobj=stream,mode='r:')as outer:\n  for layer in audit['layerMembers']:\n   with outer.extractfile(outer.getmember(layer))as content,tarfile.open(fileobj=content,mode='r|*')as inner:\n    for item in inner:\n     count+=1;require(count<=250000,'BOUNDED_LAYER_ENTRY_SET_REQUIRED');name=item.name.removeprefix('./').rstrip('/')\n     require(not name.startswith('/')and '..'not in PurePosixPath(name).parts,'SAFE_ROOTFS_MEMBER_REQUIRED')\n     if name in('.wh.app','.wh..wh..opq','app/.wh.app.jar','app/.wh..wh..opq'):found=None\n     if name=='app':require(item.isdir(),'APP_DIRECTORY_LINK_OR_SPECIAL_DENIED')\n     if name=='app/app.jar':\n      require(item.isfile()and not item.islnk()and not item.issym()and 0<item.size<=MAX,'REGULAR_BOUNDED_FINAL_APP_JAR_REQUIRED')\n      with inner.extractfile(item)as f:found=f.read(MAX+1)\n      require(len(found)==item.size,'COMPLETE_IMAGE_APP_JAR_REQUIRED')\n require(found is not None,'FINAL_IMAGE_APP_JAR_REQUIRED');return found","<sealed-rootfs>","exec"),rootfs.__dict__)

OWNER = Path('/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd')

OWNER_PLAN = 'e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938'

OWNER_RESULT = '7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618'

class Denied(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Denied(code)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(value):
    return sha(encoded(value))

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    def bad(_):
        raise Denied('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad)

def metadata(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read(path, expected=None, maximum=8388608, projection=False):
    """FD-relative no-follow traversal; retain and recheck every ancestor FD."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXACT_PATH_REQUIRED')
    if projection:
        require(path == Path('/opt/ouf/installation/active-projection.json'), 'EXACT_PROJECTION_PATH_REQUIRED')
    descriptors = []
    ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        current = Path('/')
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            current /= name
            if projection and current == Path('/opt/ouf'):
                require(info.st_uid == info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o750,
                        'APPROVED_OUF_PARENT_CUSTODY_REQUIRED')
            else:
                require(info.st_uid == 0 and not info.st_mode & 0o022, 'ROOT_ANCESTRY_REQUIRED')
            if projection and current == path.parent:
                require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                        'PRIVATE_INSTALLATION_DIRECTORY_REQUIRED')
            identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_gid, v.st_mode)
            ancestors.append((parent, name, child, identity(info)))
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= maximum, 'PRIVATE_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and metadata(info) == metadata(os.fstat(fd))
                == metadata(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'FILE_CHANGED_DURING_READ')
        require(expected is None or sha(raw) == expected, 'RETAINED_FILE_HASH_DRIFT')
        for ancestor, name, child, pin in ancestors:
            require(pin == identity(os.fstat(child))
                    == identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)), 'ANCESTRY_CHANGED_DURING_READ')
        return raw, list(metadata(info))
    finally:
        for fd in reversed(descriptors):
            os.close(fd)

def parsed(path, expected=None, maximum=8388608):
    return decode(read(path, expected, maximum)[0])

def runtime(value, ordered=True):
    state = value['State']
    require(state['Running'] is True and state.get('Paused', False) is False
            and state.get('Restarting', False) is False and type(state['Pid']) is int
            and state['Pid'] > 0, 'RUNNING_GENERATION_REQUIRED')
    mounts = value['Mounts']
    require(type(mounts) is list and len({m['Destination'] for m in mounts}) == len(mounts),
            'UNIQUE_MOUNTS_REQUIRED')
    return {'containerId': value['Id'], 'imageId': value['Image'], 'pid': state['Pid'],
            'startedAt': state['StartedAt'], 'configHash': digest(value['Config']),
            'hostConfigHash': digest(value['HostConfig']),
            'mountsHash': digest(sorted(mounts, key=lambda m: m['Destination']) if ordered else mounts),
            'networkSettingsHash': digest(value['NetworkSettings'])}

class EngineReader:
    def __init__(self, binding, references):
        self.path = Path(binding['socketPath'])
        self.pin = tuple(binding['socketBinding'])
        require(self.path.is_absolute() and '..' not in self.path.parts and len(self.pin) == 5,
                'EXACT_ENGINE_BINDING_REQUIRED')
        require(1 <= len(references) <= 8 and len(set(references)) == len(references)
                and all(re.fullmatch('[0-9a-f]{64}', r) for r in references), 'BOUNDED_EXACT_CONTAINERS_REQUIRED')
        self.paths = {'/v1.44/containers/' + r + '/json' for r in references}
        self.calls = 0
        self.maximum = 2 * len(references)

    def check(self):
        require(self.path.resolve() == self.path, 'ENGINE_SYMLINK_DENIED')
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) in (0o600, 0o660)
                and (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == self.pin,
                'ENGINE_SOCKET_DRIFT')

    def get(self, reference):
        path = '/v1.44/containers/' + reference + '/json'
        require(path in self.paths and self.calls < self.maximum, 'FINITE_CLOSED_ENGINE_GET_REQUIRED')
        self.check()
        engine_path = str(self.path)
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(engine_path)
        connection = Connection('retained-engine', timeout=5)
        try:
            self.calls += 1
            connection.request('GET', path)
            reply = connection.getresponse()
            raw = reply.read(4194305)
            require(reply.status == 200 and 0 < len(raw) <= 4194304, 'BOUNDED_ENGINE_REPLY_REQUIRED')
            self.check()
            return decode(raw)
        finally:
            connection.close()

def write_new(path, value):
    raw=encoded(value)
    require(0 < len(raw) <= 8388608, 'BOUNDED_PRIVATE_DRAFT_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    finally:os.close(fd)
    require(read(path,sha(raw))[0] == raw, 'PRIVATE_DRAFT_READBACK_REQUIRED')

SQL_MANIFEST={
  "schema": "ouf.ingestion-candidate-db-read-manifest.v1",
  "sourceCommit": "663faa03288f9ad7775382b9757e44eaba4f51ca",
  "imageId": "sha256:51a514d8e07ad7448f98a3886e0c9c6d5b50829f85d320785038a2c76eae46f3",
  "migrationCount": 18,
  "migrations": [
    {
      "version": "1",
      "script": "V1__ingestion_runtime_core.sql",
      "type": "SQL",
      "checksum": 28809713,
      "success": True,
      "resourceSha256": "8b439684da2cc31c62cfebf4ce4d939f9c8ac9b533a8c9490f5455384c064bb8"
    },
    {
      "version": "2",
      "script": "V2__durable_ack_and_replay.sql",
      "type": "SQL",
      "checksum": -1190230229,
      "success": True,
      "resourceSha256": "5e3b53341e396f7bf4ba937db2c61e96e9fdedac6420eb0de15350457ee6c528"
    },
    {
      "version": "3",
      "script": "V3__trusted_operations.sql",
      "type": "SQL",
      "checksum": 1677862093,
      "success": True,
      "resourceSha256": "a6e9eb043defdcd8590b94c690911955ec8957ba016b70967e9aef90943bedf4"
    },
    {
      "version": "4",
      "script": "V4__scheduler_and_source_health.sql",
      "type": "SQL",
      "checksum": 960152441,
      "success": True,
      "resourceSha256": "b112711bd994cff5b0bdd3671937754f6e33fd85a705a102eed23fe9f207b44c"
    },
    {
      "version": "5",
      "script": "V5__replay_execution_lifecycle.sql",
      "type": "SQL",
      "checksum": -2033393121,
      "success": True,
      "resourceSha256": "4e24738272c8fae7233d2601736662eff80d5913fbef6c88ab6dc1f511f65763"
    },
    {
      "version": "6",
      "script": "V6__protected_operational_log.sql",
      "type": "SQL",
      "checksum": -2023917644,
      "success": True,
      "resourceSha256": "5bf72f99f9c861678d3e8469ed2f71cd9cd55fccb835dbcd685e9c0d9fe6d46f"
    },
    {
      "version": "7",
      "script": "V7__execution_worker_and_snapshot.sql",
      "type": "SQL",
      "checksum": -848911848,
      "success": True,
      "resourceSha256": "48527993d3d8b50d98dc396e6d9b013410cd9db28d35fb76bff14cc23e46f9f2"
    },
    {
      "version": "8",
      "script": "V8__schema_surveillance.sql",
      "type": "SQL",
      "checksum": -61585214,
      "success": True,
      "resourceSha256": "33853cbd55d09ad901d4af6589ad36c1d4d6da1116f10a14bdb3bb2f0bd8332c"
    },
    {
      "version": "9",
      "script": "V9__runtime_issue_governance.sql",
      "type": "SQL",
      "checksum": -1413097987,
      "success": True,
      "resourceSha256": "ed0236c8b6b6c66767813a0da7d3d92457ba0968c7e4376a35b0119f22a752d9"
    },
    {
      "version": "10",
      "script": "V10__quarantine_lifecycle.sql",
      "type": "SQL",
      "checksum": 1627974653,
      "success": True,
      "resourceSha256": "41f8c2362122caa3e9e4d82df0588452a87efdde0f2c518ee47e1bd3570a03dc"
    },
    {
      "version": "11",
      "script": "V11__classified_source_resilience.sql",
      "type": "SQL",
      "checksum": -1835304128,
      "success": True,
      "resourceSha256": "97243be62e65879aed425855895456ef0f9e1579cf0b271bcbfc2b0864069e17"
    },
    {
      "version": "12",
      "script": "V12__governed_lifecycle_and_historical_replay.sql",
      "type": "SQL",
      "checksum": -1198212964,
      "success": True,
      "resourceSha256": "9fa09325985424125528420db82bce2c52f7ae75dffc7759207c7eb1666b5b2c"
    },
    {
      "version": "13",
      "script": "V13__pressure_admission_retry_budget.sql",
      "type": "SQL",
      "checksum": 1850262212,
      "success": True,
      "resourceSha256": "30402c3c225297436b9bc4e65dceca2c3ba29a3caeffc79692ea7cccf50a000d"
    },
    {
      "version": "14",
      "script": "V14__published_activation_schedule.sql",
      "type": "SQL",
      "checksum": -1324686996,
      "success": True,
      "resourceSha256": "5d6acf3516504590fe84d833803db55b87b3858a35c31a88a56e3599ceba916d"
    },
    {
      "version": "15",
      "script": "V15__human_recovery_sessions.sql",
      "type": "SQL",
      "checksum": -1837994869,
      "success": True,
      "resourceSha256": "e9abf1e1c192be62a4624f8a7ba551be28013ab3a58698a4ad13231fba29abaa"
    },
    {
      "version": "16",
      "script": "V16__incident_observation_time.sql",
      "type": "SQL",
      "checksum": -405299983,
      "success": True,
      "resourceSha256": "6fcf10b6bfbc8e71002fb9378e6a1ff45b70abb4a8f5cd863a1f207c42cb2eb9"
    },
    {
      "version": "17",
      "script": "V17__incident_publication_and_cursor.sql",
      "type": "SQL",
      "checksum": -1241321010,
      "success": True,
      "resourceSha256": "3695a5853afac3923a3428a54739d55d09cf31cc147bf46bfab8505f1c2d0716"
    },
    {
      "version": "18",
      "script": "V18__incident_publication_bookmarks.sql",
      "type": "SQL",
      "checksum": 1281376280,
      "success": True,
      "resourceSha256": "7519073ac4075c40ed743489a2aefc7f63d8dcd3b1078e6108e50104f2fa8220"
    }
  ]
}

BOOTSTRAP=Path('/etc/ouf/deploy-snapshots/ingestion-startup-bootstrap-draft-rms0te4b/draft-plan.json')

BOOTSTRAP_SHA='5dfdb800afdb82bcf4323dbe040df38e62ef935444bcaedaee444428b4a718ed'

PROGRESS={}

class PacketReader(EngineReader):
    def __init__(self,binding,references):
        super().__init__(binding,references);self.maximum+=1;self.info_read=False
    def info(self):
        require(not self.info_read and self.calls<self.maximum,'ONE_ENGINE_INFO_READ_REQUIRED')
        self.check();self.info_read=True;self.calls+=1;engine_path=str(self.path)
        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout);connection.sock.connect(engine_path)
        connection=Connection('retained-engine',timeout=5)
        try:
            connection.request('GET','/v1.44/info');reply=connection.getresponse();raw=reply.read(1048577)
            require(reply.status==200 and 0<len(raw)<=1048576,'BOUNDED_ENGINE_INFO_REQUIRED')
            self.check();value=decode(raw)
            require(value.get('ServerVersion')=='29.8.1'and value.get('OSType')=='linux'
                    and value.get('Architecture')in('x86_64','amd64')and value.get('Driver')=='overlayfs'
                    and ['driver-type','io.containerd.snapshotter.v1']in value.get('DriverStatus',[]),
                    'QUALIFIED_DOCKER29_CONTAINERD_ADAPTER_REQUIRED')
            return {k:value[k]for k in('ServerVersion','OSType','Architecture','Driver','DriverStatus')}
        finally:connection.close()

def secret_metadata(path):
    """Never open the selected key. Missing only at an existing safe parent."""
    p=Path(path);require(p.is_absolute()and '..'not in p.parts,'EXACT_OWNER_KEY_REFERENCE_REQUIRED')
    fds=[];pins=[]
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(parent)
        for name in p.parts[1:-1]:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd);s=os.fstat(fd)
            identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
            require(s.st_uid in(0,1000)and not s.st_mode&0o022,'CUSTODIED_KEY_ANCESTRY_REQUIRED')
            pins.append((parent,name,fd,identity(s)));parent=fd
        try:s=os.stat(p.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:result={'path':str(p),'state':'MISSING_AT_EXISTING_CUSTODIED_PARENT','generationAuthorized':False}
        else:
            require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==s.st_gid==10002
                    and stat.S_IMODE(s.st_mode)==0o400 and s.st_size==64,'EXISTING_OWNER_KEY_METADATA_REQUIRES_RECONCILIATION')
            result={'path':str(p),'state':'EXISTING_CONTENT_UNREAD','metadata':list(metadata(s)),
                    'contentQualified':False,'replacementAuthorized':False}
        for a,n,d,v in pins:require(v==identity(os.fstat(d))==identity(os.stat(n,dir_fd=a,follow_symlinks=False)),
                                   'KEY_ANCESTRY_CHANGED')
        return result
    finally:
        for fd in reversed(fds):os.close(fd)

def write_bytes(path,stream,maximum):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        size=0
        with os.fdopen(os.dup(fd),'wb')as output:
            for block in iter(lambda:stream.read(1048576),b''):
                size+=len(block);require(size<=maximum,'BOUNDED_PRIVATE_PACKET_FILE_REQUIRED');output.write(block)
            output.flush();os.fsync(output.fileno())
    finally:os.close(fd)

RETAINED=Path('/etc/ouf/deploy-snapshots/ingestion-rollout-packet-kkj_njiz')

NATIVE_SHA='a3e26164c58dc40a6a0cd8b13e7ab91b7ea2a2e6094b49623a7d537ec7e8af95'

NATIVE_ID='sha256:ea64511009e8fa29d1df0bab1edf0ab4656dd7336c3fae967728f0d288119a77'

class RetainedArchive:
    def __init__(self,path):
        self.path=Path(path);self.fds=[];self.pins=[]
    def __enter__(self):
        require(self.path==RETAINED/'image.native-tagless.docker.tar','EXACT_RETAINED_NATIVE_ARCHIVE_REQUIRED')
        try:
            parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.fds.append(parent)
            identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
            for name in self.path.parts[1:-1]:
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);self.fds.append(fd);s=os.fstat(fd)
                require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_ARCHIVE_ANCESTRY_REQUIRED')
                self.pins.append((parent,name,fd,identity(s)));parent=fd
            require(stat.S_IMODE(os.fstat(parent).st_mode)==0o700,'PRIVATE_RETAINED_PACKET_CONTEXT_REQUIRED')
            require(set(os.listdir(parent))=={'image.original.docker.tar','image.native-tagless.docker.tar'},
                    'EXACT_STOP_BEFORE_CONFIG_STAGING_REQUIRED')
            self.parent=parent;self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);self.fds.append(self.fd)
            s=os.fstat(self.fd);self.file_pin=metadata(s)
            require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
                    and s.st_nlink==1 and 0<s.st_size<=custody.LIMIT,'PRIVATE_RETAINED_ARCHIVE_CUSTODY_REQUIRED')
            self.stream=os.fdopen(os.dup(self.fd),'rb');return self
        except BaseException:
            for fd in reversed(self.fds):os.close(fd)
            raise
    def recheck(self):
        require(self.file_pin==metadata(os.fstat(self.fd))==metadata(os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False)),
                'RETAINED_NATIVE_ARCHIVE_CHANGED')
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
        for p,n,fd,pin in self.pins:
            require(pin==identity(os.fstat(fd))==identity(os.stat(n,dir_fd=p,follow_symlinks=False)),'RETAINED_ARCHIVE_ANCESTRY_CHANGED')
        require(set(os.listdir(self.parent))=={'image.original.docker.tar','image.native-tagless.docker.tar'},
                'RETAINED_CONTEXT_CHANGED')
    def __exit__(self,*_):
        try:self.stream.close()
        finally:
            for fd in reversed(self.fds):os.close(fd)
import tarfile

STAGED_CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-rollout-packet-reconcile-0wd4wyuf')

def native_header():
    """Recheck existing bytes; reuse the completed exact-image/JAR qualification."""
    with RetainedArchive(RETAINED/'image.native-tagless.docker.tar')as selected:
        require(custody.hashed(selected.stream,custody.LIMIT)[0]==NATIVE_SHA,'QUALIFIED_RETAINED_NATIVE_ARCHIVE_BYTES_REQUIRED')
        selected.stream.seek(0)
        with tarfile.open(fileobj=selected.stream,mode='r:')as archive:
            rows=archive.getmembers();require(0<len(rows)<=512 and len({r.name for r in rows})==len(rows),'BOUNDED_UNIQUE_QUALIFIED_ARCHIVE_REQUIRED')
            def small(name,maximum):
                row=archive.getmember(name);require(row.isfile()and 0<row.size<=maximum,'BOUNDED_REGULAR_QUALIFIED_IMAGE_HEADER_REQUIRED')
                with archive.extractfile(row)as f:return f.read(maximum+1)
            manifest=decode(small('manifest.json',131072))
            require(type(manifest)is list and len(manifest)==1 and not manifest[0].get('RepoTags'),'EXACT_TAGLESS_IMAGE_HEADER_REQUIRED')
            raw=small(manifest[0]['Config'],2097152)
            require('sha256:'+sha(raw)==package.IMAGE,'EXACT_QUALIFIED_CONFIGURATION_IMAGE_REQUIRED')
            image=decode(raw)
            require(image['config']['Labels']['org.opencontainers.image.revision']==package.SOURCE
                    and image['os']=='linux'and image['architecture']=='amd64','EXACT_QUALIFIED_IMAGE_SOURCE_PLATFORM_REQUIRED')
            native_manifest=small('blobs/sha256/'+NATIVE_ID[7:],131072)
            require('sha256:'+sha(native_manifest)==NATIVE_ID,'EXACT_QUALIFIED_NATIVE_MANIFEST_REQUIRED')
        selected.recheck()
        return {'configurationImageId':package.IMAGE,'nativeImageId':NATIVE_ID,'sourceCommit':package.SOURCE,
                'imageConfig':image['config'],'rootfs':image['rootfs'],
                'nativeArchiveBinding':{'path':str(selected.path),'sha256':NATIVE_SHA,'metadata':list(selected.file_pin)},
                'qualificationRunId':39384690724,'exactJarAnd18SqlQualificationReused':True,
                'archiveAuditReplayed':False,'archiveRecreated':False,'packageDownloaded':False,'targetApplyAuthorized':False}

def retained_staged_config(old_config,old_raw):
    """Read the completed proposal in place; no chmod/chown/new staging."""
    path=STAGED_CONTEXT/'apisix-config.proposed.yaml';selected=old_config['metadata']
    gateway._EXISTING_CONFIG_CUSTODY[str(path)]={'parents':{},'file':(selected[2],selected[3],stat.S_IMODE(selected[4]))}
    raw,binding=gateway.private_config(path)
    fd=os.open(STAGED_CONTEXT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
                and set(os.listdir(fd))=={'apisix-config.proposed.yaml'},'EXACT_STOPPED_FRAME_CONTEXT_REQUIRED')
    finally:os.close(fd)
    require(raw==frames.expose_owner_environment(old_raw)and raw!=old_raw
            and binding['metadata'][2:5]==selected[2:5],'EXACT_ALREADY_STAGED_CONFIG_BYTES_AND_METADATA_REQUIRED')
    return binding

def main():
    require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_NO_ARGUMENTS_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_FRAME_RECONCILIATION_DEADLINE'));signal.alarm(120);os.umask(0o077)
    PROGRESS.update(retainedContextPath=str(RETAINED),retainedStagedContextPath=str(STAGED_CONTEXT),phase='EXACT_RETAINED_LINEAGE')
    draft=parsed(BOOTSTRAP,BOOTSTRAP_SHA);owner=parsed(OWNER/'execution-plan.json',OWNER_PLAN)
    completed=parsed(OWNER/'update-result.json',OWNER_RESULT)
    require(completed['complete']is True and completed['planHash']==OWNER_PLAN
            and draft['schema']=='ouf.ingestion-startup-bootstrap-draft.v1'and draft['runtimeAuthorityIssued']is False,
            'EXACT_COMPLETED_OWNER7_AND_BOOTSTRAP_REQUIRED')
    old_logical=digest({'bootstrap':BOOTSTRAP_SHA,'zip':package.ZIP_SHA,'preparation':'ouf.ingestion-rollout-packet.v1'})
    old_claim=OWNER.parent/('ingestion-rollout-packet-'+old_logical+'.claim.json');old=parsed(old_claim)
    require(old=={'contextPath':str(RETAINED),'logicalRef':old_logical,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False},
            'EXACT_ORIGINAL_RETAINED_PACKET_CLAIM_REQUIRED')
    prior_logical=digest({'predecessor':old,'bootstrap':BOOTSTRAP_SHA,'reconciliation':'ouf.ingestion-rollout-packet-reconcile.v1'})
    prior_claim=OWNER.parent/('ingestion-rollout-packet-reconcile-'+prior_logical+'.claim.json');prior=parsed(prior_claim)
    require(prior=={'contextPath':str(STAGED_CONTEXT),'predecessorContextPath':str(RETAINED),'logicalRef':prior_logical,
                    'runtimeAuthorityIssued':False,'automaticReplayAllowed':False},'EXACT_RETAINED_CONFIG_RECONCILIATION_CLAIM_REQUIRED')
    logical=digest({'prior':prior,'bootstrap':BOOTSTRAP_SHA,'profile':'ouf.ingestion-frame-mac-reconcile.v2'})
    claim=OWNER.parent/('ingestion-frame-mac-reconcile-'+logical+'.claim.json')
    require(not os.path.lexists(claim),'FRAME_RECONCILIATION_ALREADY_CLAIMED_NO_REPLAY')
    PROGRESS['phase']='RECHECK_QUALIFIED_ARCHIVE_HEADER';candidate=native_header()
    pins=draft['expectedRuntimeBindings'];require(set(pins)=={'ingestion','gateway'}
            and all(pins[n]==owner['currentApplications'][n]for n in pins),'EXACT_RETAINED_RUNTIME_BINDINGS_REQUIRED')
    reader=PacketReader(owner['engine'],[p['containerId']for p in pins.values()]);info=reader.info()
    actual={n:reader.get(p['containerId'])for n,p in pins.items()}
    require(all(runtime(actual[n])==p for n,p in pins.items()),'RETAINED_RUNTIME_GENERATION_DRIFT')
    config_binding=owner['gateway']['transport']['configBinding'];old_raw,old_config=gateway.private_config(config_binding['path'],config_binding)
    mounts=[v for v in actual['gateway']['Mounts']if v['Destination']==frames.CONFIG_DESTINATION]
    require(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['Source']==config_binding['path']and mounts[0]['RW']is False,
            'EXACT_SELECTED_GATEWAY_READ_ONLY_CONFIG_MOUNT_REQUIRED')
    PROGRESS['phase']='RECONCILE_ALREADY_STAGED_CONFIG';staged=retained_staged_config(old_config,old_raw)
    key=draft['gateway']['environmentAddition'][frames.OWNER_ENV]['path']
    require(key==owner['bindingPlan']['candidatePayload']['secrets']['references']['ingestionReadOwnerKey']
            ==draft['ingestion']['readOnlyBindAddition']['Source'],'EXACT_PUBLISHED_OWNER_KEY_REFERENCE_REQUIRED')
    key_state=secret_metadata(key)
    PROGRESS['phase']='RECONCILE_COMPLETE_MAC_FRAME_TEMPLATES'
    complete={n:frames.frame(n,v,NATIVE_ID if n=='ingestion'else v['Image'],candidate['imageConfig'],draft,staged['path'])for n,v in actual.items()}
    require(all(runtime(reader.get(p['containerId']))==pins[n]for n,p in pins.items()),'RUNTIME_CHANGED_DURING_FRAME_RECONCILIATION')
    gateway.private_config(config_binding['path'],config_binding);gateway.private_config(staged['path'],staged)
    require(secret_metadata(key)==key_state and parsed(BOOTSTRAP,BOOTSTRAP_SHA)==draft
            and parsed(OWNER/'execution-plan.json',OWNER_PLAN)==owner and parsed(OWNER/'update-result.json',OWNER_RESULT)==completed
            and parsed(old_claim)==old and parsed(prior_claim)==prior,'RETAINED_FRAME_INPUT_SELECTION_CHANGED')
    with RetainedArchive(RETAINED/'image.native-tagless.docker.tar')as a:
        require(list(a.file_pin)==candidate['nativeArchiveBinding']['metadata'],'RETAINED_ARCHIVE_METADATA_DRIFT');a.recheck()
    # Compile and validate before creating any successor claim/context. Completed
    # archive preparation and config staging are never dispatched again.
    context=Path(tempfile.mkdtemp(prefix='ingestion-frame-mac-reconcile-',dir=OWNER.parent));os.chmod(context,0o700)
    PROGRESS['contextPath']=str(context)
    write_new(claim,{'contextPath':str(context),'logicalRef':logical,'retainedStagedContextPath':str(STAGED_CONTEXT),
                     'automaticReplayAllowed':False,'runtimeAuthorityIssued':False})
    inputs={'candidate':candidate,'expectedRuntimeBindings':pins,'gatewayConfigBefore':old_config,'retainedGatewayConfig':staged,
            'dedicatedOwnerKey':key_state,'retainedClaims':{'original':old,'staging':prior},'runtimeAuthorityIssued':False}
    write_new(context/'verified-inputs.json',inputs)
    plan={'schema':'ouf.ingestion-rollout-private-packet.v3','kind':'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY',
          'bootstrapBinding':{'path':str(BOOTSTRAP),'sha256':BOOTSTRAP_SHA},'ownerPlanSha256':OWNER_PLAN,
          'verifiedInputsHash':digest(inputs),'retainedContextPath':str(RETAINED),'retainedStagedContextPath':str(STAGED_CONTEXT),
          **inputs,'engineAdapter':info,'frames':complete,'routeDraft':draft['routeDraft'],
          'unprovenGates':['CURRENT_HUMAN_AND_SEPARATE_NATIVE_REVIEW','SIGNED_RUNTIME_EXECUTOR_QUALIFICATION',
             'DEDICATED_KEY_GENERATION_OR_EXISTING_KEY_CUSTODY_AUTHORITY','CURRENT_OWNER7_STRONG_ETAG_AND_PAYLOAD',
             'LIVE_GATEWAY82_ROUTE_MAP','FRESH_DATABASE_ADMISSION_BEFORE_EFFECTS'],
          'nativeCreationRoundTripQualified':False,'runtimeExecutorQualified':False,'databaseAdmissionProven':False,
          'automaticReplayAllowed':False,'budgetReset':False,'newLoginAllowed':False,'targetApplyAuthorized':False}
    write_new(context/'packet-plan.json',plan)
    report={'schema':'ouf.ingestion-frame-mac-reconcile.v2','complete':True,'status':'RECONCILED_COMPLETE_FRAMES_NO_AUTHORITY',
            'contextPath':str(context),'packetPlanHash':digest(plan),'verifiedInputsHash':digest(inputs),
            'retainedContextPath':str(RETAINED),'retainedStagedContextPath':str(STAGED_CONTEXT),'retainedClaimsUnchanged':True,
            'qualifiedArchiveBytesRechecked':True,'completedArchiveAuditReplayed':False,'candidateArchiveRecreated':False,
            'candidatePackageDownloaded':False,'completedGatewayConfigStagingReplayed':False,
            'gatewaySelectedConfigMetadataPreserved':True,'legacyMacNormalizedModules':[n for n,p in complete.items()if p['legacyContainerMacMovedToExplicitEndpoints']],
            'observedEndpointMacsAndAddressesPreserved':True,'engineGetRequests':reader.calls,'maximumEngineGetRequests':5,
            'runtimeBindingsStable':True,'dedicatedKeyMetadataState':key_state['state'],'dedicatedKeyFilesOpened':0,
            'secretValuesGenerated':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,'humanCredentialJournalsRead':0,
            'oauthRequests':0,'ownerRequests':0,'gatewayRequests':0,'databaseCalls':0,'containerLifecycleOperations':0,
            'candidateImageImported':False,'completedOwnerActionReplayed':False,'completedPublicationReplayed':False,
            'completedDbPreflightReplayed':False,'completedBootstrapDraftReplayed':False,'newLoginPerformed':False,
            'refreshPerformed':False,'windowExtended':False,'runtimeAuthorityIssued':False,'runtimeExecutorQualified':False,
            'nativeCreationRoundTripQualified':False,'databaseAdmissionProven':False,'automaticReplayAllowed':False,'budgetReset':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
    write_new(context/'preparation-result.json',report)
    fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    PROGRESS['phase']='COMPLETE';print(encoded(report).decode(),flush=True)

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt)as error:
        code=str(error)if type(error)in(Denied,ValueError,custody.ImageCustodyDenied,gateway.Denied)and re.fullmatch('[A-Z][A-Z0-9_]{1,127}',str(error))else 'PRIVATE_DETAILS_REDACTED'
        print(encoded({'schema':'ouf.ingestion-frame-mac-reconcile.v2','complete':False,'status':'STOP_RECONCILE',
                       'reasonCode':code,'checkpoint':PROGRESS,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
                       'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}).decode(),flush=True)
        raise SystemExit(2)

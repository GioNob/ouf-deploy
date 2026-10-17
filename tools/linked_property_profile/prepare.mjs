import {readFile,writeFile} from 'node:fs/promises';
import {prepare} from './linked-property-profile.mjs';

const [snapshotPath,proposalPath,outputPath,...extra]=process.argv.slice(2);
if(!snapshotPath||!proposalPath||!outputPath||extra.length)throw new Error('USAGE: node prepare.mjs owner-snapshot.json proposal.json private-preparation.json');
async function read(path){const raw=await readFile(path);if(raw.length>4194304)throw new Error('INPUT_SIZE_LIMIT');return JSON.parse(raw.toString('utf8'));}
const result=prepare(await read(snapshotPath),await read(proposalPath));
await writeFile(outputPath,JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
console.log(JSON.stringify({schema:result.schema,sourceId:result.sourceId,propertyCount:result.changes.length,
  candidateDigest:result.candidateDigest,readyForActivation:false,profilePublications:0,jobsRetried:0}));

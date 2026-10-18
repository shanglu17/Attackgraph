import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

// Reconstruct a checkout of the uncommitted delivery without staging/committing
// or copying ignored local state. Every overlay path is recorded for review.
const root=process.cwd();
const git=(...args)=>execFileSync("git",["-c","safe.directory="+root.split(path.sep).join("/"),...args],{encoding:"utf8"}).trim();
const output=path.resolve(".tmp/clean-source-"+Date.now());
fs.mkdirSync(output,{recursive:true});
const archive=path.resolve(".tmp/clean-baseline.zip");
git("archive","--format=zip","--output="+archive,"HEAD");
execFileSync("tar",["-xf",archive,"-C",output]);
const lines=text=>text?text.split(/\r?\n/).filter(Boolean):[];
const added=lines(git("-c","core.quotepath=false","ls-files","--others","--exclude-standard"));
const modified=lines(git("-c","core.quotepath=false","diff","--name-only","--diff-filter=ACMR"));
const deleted=lines(git("-c","core.quotepath=false","diff","--name-only","--diff-filter=D"));
const whitelist=[...new Set([...added,...modified])].sort();
for(const name of [...whitelist,...deleted]){
  const target=path.resolve(output,name);
  if(!target.startsWith(output+path.sep))throw new Error("Path escapes clean source: "+name);
  if(deleted.includes(name)){fs.rmSync(target,{force:true});continue;}
  if(/(^|\/)(node_modules|dist|\.tmp|\.npm-cache|\.git)(\/|$)|(^|\/)\.env$|DemoApp|DemoContext|\/demo\/|start-demo/.test(name))throw new Error("Excluded delivery path: "+name);
  fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(root,name),target);
}
const manifest={baseline:git("rev-parse","HEAD"),output,overlay:whitelist.map(name=>({name,sha256:createHash("sha256").update(fs.readFileSync(path.join(root,name))).digest("hex")})),deleted};
fs.writeFileSync(path.join(output,"source-manifest.json"),JSON.stringify(manifest,null,2));
console.log(JSON.stringify({baseline:manifest.baseline,output,overlay_files:whitelist.length,deleted_files:deleted.length},null,2));

import { createServer, request } from "node:http";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";

// Serve the real production artifacts and transparently proxy the real API.
// No model, analysis or persistence is implemented here.
const directory=fileURLToPath(new URL("../apps/frontend/dist/",import.meta.url));
const backend=new URL(process.env.ASTRA_BACKEND_URL??"http://127.0.0.1:4000");
const port=Number(process.env.FRONTEND_PORT??5173);
const types={".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",".svg":"image/svg+xml",".png":"image/png",".json":"application/json"};
const server=createServer(async(req,res)=>{
  if(req.url?.startsWith("/api/")){
    const upstream=request(new URL(req.url,backend),{method:req.method,headers:{...req.headers,host:backend.host}},reply=>{res.writeHead(reply.statusCode??502,reply.headers);reply.pipe(res);});
    upstream.on("error",()=>{if(!res.headersSent)res.writeHead(502,{"content-type":"application/json"});res.end(JSON.stringify({message:"后端不可用，请检查 API 服务"}));});req.pipe(upstream);return;
  }
  try{
    const pathname=decodeURIComponent(new URL(req.url??"/","http://localhost").pathname);
    const filename=pathname==="/"||!path.extname(pathname)?"index.html":pathname.slice(1);
    const absolute=path.resolve(directory,filename);
    if(!absolute.startsWith(path.resolve(directory)+path.sep))throw new Error("Invalid path");
    if(!(await stat(absolute)).isFile())throw new Error("Missing file");
    const original=await readFile(absolute);const extension=path.extname(absolute);
    const compress=/\bgzip\b/.test(req.headers["accept-encoding"]??"")&&[".html",".js",".css",".json",".svg"].includes(extension);
    const body=compress?gzipSync(original):original;
    res.writeHead(200,{"content-type":types[extension]??"application/octet-stream","cache-control":"no-store","vary":"Accept-Encoding","content-length":body.length,...(compress?{"content-encoding":"gzip"}:{})});res.end(body);
  }catch{res.writeHead(404,{"content-type":"text/plain; charset=utf-8"});res.end("Not found");}
});
server.listen(port,"127.0.0.1",()=>console.log(`Built workbench: http://127.0.0.1:${port}`));
process.on("SIGINT",()=>server.close(()=>process.exit(0)));

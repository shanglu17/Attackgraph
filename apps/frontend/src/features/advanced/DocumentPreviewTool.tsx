import { useWorkbench } from "../../app/WorkspaceProvider";
import { downloadBlob } from "../reports/resultExport";
export default function DocumentPreviewTool(){
  const {state,perform,patch}=useWorkbench();const parsed=state.documentPreview;
  return <section className="panel"><h3>AFHA / FHA 文档解析</h3><p>提取 DOCX 中的失效状态表，供工程证据核对。解析记录尚未写入系统模型，不直接参与 DPS 分析。</p>
    <label className="field-stack">选择 FHA DOCX<input className="input-field" type="file" accept=".docx" disabled={state.busy} onChange={e=>{const file=e.target.files?.[0];e.target.value="";if(!file)return;patch({documentPreview:null});void perform(async()=>{const {parseFhaDocument}=await import("../../fhaDocument");patch({documentPreview:await parseFhaDocument(file),message:"文档解析完成，请核对提取记录并在工程审查中关联来源证据。"});});}}/></label>
    {!parsed?<p>请选择包含“失效状态及其编号”表头的 DOCX 文件。文档解析器在实际读取时加载。</p>:<><p>已解析 {parsed.payload.failure_conditions.length} 条 FHA 记录。</p><pre className="scroll-panel">{JSON.stringify(parsed.payload,null,2)}</pre><button className="button" onClick={()=>downloadBlob(new Blob([JSON.stringify({contract_version:"document-extraction.v1",status:"uncommitted_extraction",...parsed},null,2)],{type:"application/json"}),"FHA-文档解析记录.json")}>下载文档解析记录</button></>}
  </section>;
}

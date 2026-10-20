import { useWorkbench } from "../../app/WorkspaceProvider";
export function RunLoadStatus(){
  const {state,loadRun}=useWorkbench();
  return <>
    {state.historyBusy&&<p role="status">正在读取所选分析记录…</p>}
    {state.runError&&<p role="alert">{state.runError} <button className="button" disabled={state.historyBusy} onClick={()=>void loadRun()}>重试加载分析结果</button></p>}
  </>;
}

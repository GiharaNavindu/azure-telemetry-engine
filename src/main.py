import os
import json
import asyncio
import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from openai import AzureOpenAI
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aiops-controller")

app = FastAPI(title="AIOps Incident Analyzer")

WATCH_NAMESPACE = os.getenv("WATCH_NAMESPACE", "incident-demo")
AIOPS_NAMESPACE = os.getenv("AIOPS_NAMESPACE", "aiops-system")
CONFIGMAP_NAME = os.getenv("AIOPS_REPORT_CONFIGMAP", "aiops-latest-incident-report")

try:
    config.load_incluster_config()
except:
    config.load_kube_config()

core_v1 = client.CoreV1Api()

class IncidentRCA(BaseModel):
    status: str
    incident_type: Optional[str] = None
    affected_resource: Optional[str] = None
    symptom: Optional[str] = None
    root_cause: Optional[str] = None
    file_to_fix: Optional[str] = None
    recommended_safe_next_steps: Optional[str] = None
    confidence: str

def gather_evidence():
    evidence = {"pods": [], "endpoints": []}
    try:
        pods = core_v1.list_namespaced_pod(WATCH_NAMESPACE)
        for p in pods.items:
            statuses = []
            struggling = False
            if p.status.container_statuses:
                for c in p.status.container_statuses:
                    if c.state:
                        if c.state.waiting:
                            reason = c.state.waiting.reason
                            statuses.append({"reason": reason})
                            if reason in ['CrashLoopBackOff', 'Error', 'BackOff', 'ImagePullBackOff', 'ErrImagePull']:
                                struggling = True
                        if c.state.terminated:
                            reason = c.state.terminated.reason
                            statuses.append({"reason": reason})
                            if reason in ['CrashLoopBackOff', 'Error', 'BackOff', 'ImagePullBackOff', 'ErrImagePull']:
                                struggling = True
                        if not c.state.running:
                            struggling = True

            pod_logs = ""
            if struggling:
                try:
                    pod_logs = core_v1.read_namespaced_pod_log(name=p.metadata.name, namespace=WATCH_NAMESPACE, tail_lines=20)
                except Exception as log_err:
                    logger.warning(f"Could not read logs for pod {p.metadata.name}: {log_err}")
                    pod_logs = f"Error reading logs: {str(log_err)}"

            evidence["pods"].append({
                "name": p.metadata.name,
                "statuses": statuses,
                "logs": pod_logs
            })

        endpoints = core_v1.list_namespaced_endpoints(WATCH_NAMESPACE)
        for ep in endpoints.items:
            addresses = []
            if ep.subsets:
                for sub in ep.subsets:
                    if sub.addresses:
                        addresses.extend([a.ip for a in sub.addresses])
            evidence["endpoints"].append({"name": ep.metadata.name, "addresses": addresses})
    except Exception as e:
        logger.error(f"K8s API error: {e}")
    return evidence

def analyze_with_ai(evidence):
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    key = os.getenv("AZURE_OPENAI_KEY")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2026-03-17")
    
    if not all([endpoint, key, deployment]):
        return json.dumps({"status": "error", "message": "Missing OpenAI credentials"})

    has_issue = False
    for p in evidence["pods"]:
        if p.get("logs"):
            has_issue = True
        for s in p.get("statuses", []):
            if s.get("reason") in ["ImagePullBackOff", "ErrImagePull", "BackOff", "CrashLoopBackOff", "Error"]:
                has_issue = True
    for ep in evidence["endpoints"]:
        if len(ep["addresses"]) == 0:
            has_issue = True

    if not has_issue:
        return json.dumps({"status": "healthy", "message": "No supported incident detected."})

    try:
        # Gracefully handle the endpoint if it contains the trailing path
        # clean_endpoint = endpoint.split("/openai")[0] 
        client_ai = AzureOpenAI(azure_endpoint=endpoint, api_key=key, api_version=api_version)
        
        prompt = (
            f"Analyze this K8s evidence in namespace {WATCH_NAMESPACE}:\n{json.dumps(evidence)}\n"
            "Identify if there's a bad image tag, empty service endpoints, or runtime application errors. "
            "Examine any application logs appended in the pod evidence (e.g. in `evidence['pods']`) to diagnose "
            "runtime errors (such as missing environment configurations, db connection failures, or uncaught exceptions) "
            "and suggest safe next steps. The repo is 'aks-gitops-sample-app'."
        )
        
        response = client_ai.beta.chat.completions.parse(
            model=deployment,
            messages=[{"role": "system", "content": "You are an SRE AI. Output strict JSON."}, {"role": "user", "content": prompt}],
            response_format=IncidentRCA,
            temperature=0.0
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Azure OpenAI Error: {e}")
        return json.dumps({"status": "error", "message": f"AI Engine Failed: {str(e)}"})

def update_configmap(report_json):
    body = client.V1ConfigMap(
        api_version="v1", kind="ConfigMap",
        metadata=client.V1ObjectMeta(name=CONFIGMAP_NAME, namespace=AIOPS_NAMESPACE),
        data={"report.json": report_json}
    )
    try:
        core_v1.replace_namespaced_config_map(name=CONFIGMAP_NAME, namespace=AIOPS_NAMESPACE, body=body)
        logger.info("Successfully updated RCA ConfigMap.")
    except ApiException as e:
        if e.status == 404:
            try:
                core_v1.create_namespaced_config_map(namespace=AIOPS_NAMESPACE, body=body)
                logger.info("Successfully created RCA ConfigMap.")
            except Exception as ex:
                logger.error(f"Failed to create ConfigMap: {ex}")
        else:
            logger.error(f"K8s API Exception during replace: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in update_configmap: {e}")

async def polling_loop():
    from kubernetes import watch
    
    while True:
        w = watch.Watch()
        try:
            logger.info(f"Starting Kubernetes watch stream for namespace {WATCH_NAMESPACE}...")
            
            def process_events():
                for event in w.stream(core_v1.list_namespaced_pod, namespace=WATCH_NAMESPACE, timeout_seconds=300):
                    event_type = event.get('type')
                    pod = event.get('object')
                    if not pod:
                        continue
                    
                    if event_type in ['ADDED', 'MODIFIED']:
                        anomaly_detected = False
                        if pod.status and pod.status.container_statuses:
                            for c in pod.status.container_statuses:
                                if c.state:
                                    if c.state.waiting:
                                        reason = c.state.waiting.reason
                                        if reason in ['CrashLoopBackOff', 'ErrImagePull', 'BackOff', 'ImagePullBackOff', 'Error']:
                                            anomaly_detected = True
                                            break
                                    if c.state.terminated:
                                        reason = c.state.terminated.reason
                                        if reason in ['CrashLoopBackOff', 'ErrImagePull', 'BackOff', 'ImagePullBackOff', 'Error']:
                                            anomaly_detected = True
                                            break
                        
                        if anomaly_detected:
                            logger.info(f"Anomaly detected in pod {pod.metadata.name} (type: {event_type}). Triggering analysis...")
                            try:
                                evidence = gather_evidence()
                                report = analyze_with_ai(evidence)
                                update_configmap(report)
                            except Exception as ex:
                                logger.error(f"Error in event handler analysis: {ex}")
            
            await asyncio.to_thread(process_events)
            
        except Exception as e:
            logger.error(f"Watch connection error: {e}. Retrying in 5 seconds...")
            try:
                w.stop()
            except:
                pass
            await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(polling_loop())

@app.get("/aiops", response_class=HTMLResponse)
async def dashboard():
    import html
    report_data = "{}"
    try:
        cm = core_v1.read_namespaced_config_map(name=CONFIGMAP_NAME, namespace=AIOPS_NAMESPACE)
        if cm.data and "report.json" in cm.data:
            report_data = cm.data["report.json"]
    except Exception as e:
        logger.error(f"Error reading configmap: {e}")
    
    try:
        parsed_report = json.loads(report_data)
        if not isinstance(parsed_report, dict):
            raise ValueError("Parsed JSON is not a dictionary")
    except Exception as e:
        logger.error(f"Error parsing report data: {e}")
        parsed_report = {
            "status": "error",
            "symptom": f"Failed to parse report data: {report_data}",
            "confidence": "Low"
        }

    status = parsed_report.get("status") or "Unknown"
    
    # Render healthy screen if status is healthy
    if str(status).lower() == "healthy":
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AIOps Telemetry Dashboard</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <meta http-equiv="refresh" content="10">
        </head>
        <body class="bg-gray-950 text-gray-100 font-sans antialiased p-8 min-h-screen flex items-center justify-center">
            <div class="max-w-md w-full bg-gray-900 rounded-2xl shadow-2xl border border-emerald-500/20 p-8 text-center">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 text-emerald-400 mb-6 border border-emerald-500/20">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                </div>
                <h1 class="text-2xl font-bold text-white mb-2">All Systems Operational</h1>
                <p class="text-gray-400 text-sm mb-6">Watching namespace: <span class="text-blue-400 font-mono">{WATCH_NAMESPACE}</span></p>
                <div class="inline-flex items-center space-x-2 bg-emerald-500/10 text-emerald-400 px-4 py-2 rounded-full border border-emerald-500/25 text-xs font-semibold uppercase tracking-wider">
                    <span class="relative flex h-2 w-2">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                    <span>Healthy</span>
                </div>
            </div>
        </body>
        </html>
        """

    # Safely extract and escape all fields for rendering
    status_esc = html.escape(str(status))
    incident_type = html.escape(str(parsed_report.get("incident_type") or "Unknown"))
    affected_resource = html.escape(str(parsed_report.get("affected_resource") or "None Detected"))
    symptom = html.escape(str(parsed_report.get("symptom") or "No symptoms recorded"))
    root_cause = html.escape(str(parsed_report.get("root_cause") or "Undetermined"))
    file_to_fix = html.escape(str(parsed_report.get("file_to_fix") or "None"))
    recommended_safe_next_steps = html.escape(str(parsed_report.get("recommended_safe_next_steps") or "No recommended steps provided"))
    confidence = html.escape(str(parsed_report.get("confidence") or "Low"))

    # Determine confidence badge colors
    conf_lower = confidence.lower()
    if "high" in conf_lower:
        confidence_bg = "bg-emerald-500/10"
        confidence_border = "border-emerald-500/20"
        confidence_text = "text-emerald-400"
    elif "medium" in conf_lower:
        confidence_bg = "bg-amber-500/10"
        confidence_border = "border-amber-500/20"
        confidence_text = "text-amber-400"
    else:
        confidence_bg = "bg-rose-500/10"
        confidence_border = "border-rose-500/20"
        confidence_text = "text-rose-400"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AIOps Telemetry Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <meta http-equiv="refresh" content="10">
    </head>
    <body class="bg-gray-950 text-gray-100 font-sans antialiased p-8 min-h-screen">
        <div class="max-w-6xl mx-auto">
            <!-- Header Section -->
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 border-b border-gray-800 pb-6">
                <div>
                    <h1 class="text-3xl font-bold text-white tracking-tight">AIOps Telemetry Engine</h1>
                    <p class="text-sm text-gray-400 mt-1">Watching namespace: <span class="text-blue-400 font-mono">{WATCH_NAMESPACE}</span></p>
                </div>
                <div class="mt-4 md:mt-0 flex items-center space-x-3 bg-gray-900 px-4 py-2 rounded-full border border-gray-800">
                    <span class="relative flex h-3 w-3">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-3 w-3 bg-rose-500"></span>
                    </span>
                    <span class="text-sm font-medium text-gray-300">Active Incident Detected</span>
                </div>
            </div>

            <!-- Top Section Metrics/Badges -->
            <div class="flex flex-wrap gap-4 mb-8">
                <!-- Status Badge -->
                <div class="flex items-center space-x-2 bg-rose-500/10 border border-rose-500/20 px-3 py-1.5 rounded-lg text-sm">
                    <span class="text-gray-400 font-medium">Status:</span>
                    <span class="text-rose-400 font-semibold">{status_esc}</span>
                </div>
                <!-- Incident Type Badge -->
                <div class="flex items-center space-x-2 bg-blue-500/10 border border-blue-500/20 px-3 py-1.5 rounded-lg text-sm">
                    <span class="text-gray-400 font-medium">Incident Type:</span>
                    <span class="text-blue-400 font-semibold">{incident_type}</span>
                </div>
                <!-- Confidence Level Badge -->
                <div class="flex items-center space-x-2 {confidence_bg} border {confidence_border} px-3 py-1.5 rounded-lg text-sm">
                    <span class="text-gray-400 font-medium">Confidence:</span>
                    <span class="{confidence_text} font-semibold">{confidence}</span>
                </div>
            </div>

            <!-- Cards Layout -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Card 1: Symptom & Affected Resource -->
                <div class="bg-gray-900/60 rounded-xl border border-amber-500/30 p-6 flex flex-col justify-between">
                    <div>
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="p-2 bg-amber-500/10 rounded-lg text-amber-400 border border-amber-500/25">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Symptom & Resource</h3>
                        </div>
                        <div class="space-y-4">
                            <div>
                                <span class="text-xs font-semibold text-amber-400 uppercase tracking-wider">Affected Resource</span>
                                <p class="text-sm font-mono text-gray-200 mt-1 bg-gray-950 p-2 rounded border border-gray-800 break-all">{affected_resource}</p>
                            </div>
                            <div>
                                <span class="text-xs font-semibold text-amber-400 uppercase tracking-wider">Symptom</span>
                                <p class="text-sm text-gray-300 mt-1 leading-relaxed">{symptom}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Card 2: Root Cause & Identified File -->
                <div class="bg-gray-900/60 rounded-xl border border-rose-500/30 p-6 flex flex-col justify-between">
                    <div>
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="p-2 bg-rose-500/10 rounded-lg text-rose-400 border border-rose-500/25">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Root Cause Analysis</h3>
                        </div>
                        <div class="space-y-4">
                            <div>
                                <span class="text-xs font-semibold text-rose-400 uppercase tracking-wider">File to Fix</span>
                                <p class="text-sm font-mono text-gray-200 mt-1 bg-gray-950 p-2 rounded border border-gray-800 break-all">{file_to_fix}</p>
                            </div>
                            <div>
                                <span class="text-xs font-semibold text-rose-400 uppercase tracking-wider">Root Cause</span>
                                <p class="text-sm text-gray-300 mt-1 leading-relaxed">{root_cause}</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Card 3: Recommended Safe Next Steps -->
                <div class="bg-gray-900/60 rounded-xl border border-emerald-500/30 p-6 flex flex-col justify-between">
                    <div>
                        <div class="flex items-center space-x-3 mb-4">
                            <div class="p-2 bg-emerald-500/10 rounded-lg text-emerald-400 border border-emerald-500/25">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path>
                                </svg>
                            </div>
                            <h3 class="text-lg font-semibold text-white">Recommended Actions</h3>
                        </div>
                        <div class="space-y-4">
                            <div>
                                <span class="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Safe Next Steps</span>
                                <p class="text-sm text-gray-300 mt-1 leading-relaxed">{recommended_safe_next_steps}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
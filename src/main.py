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
            if p.status.container_statuses:
                for c in p.status.container_statuses:
                    if c.state.waiting:
                        statuses.append({"reason": c.state.waiting.reason})
            evidence["pods"].append({"name": p.metadata.name, "statuses": statuses})

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
        for s in p.get("statuses", []):
            if s.get("reason") in ["ImagePullBackOff", "ErrImagePull", "BackOff"]:
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
        
        prompt = f"Analyze this K8s evidence in namespace {WATCH_NAMESPACE}:\n{json.dumps(evidence)}\nIdentify if there's a bad image tag or empty service endpoints. The repo is 'aks-gitops-sample-app'."
        
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
    while True:
        try:
            evidence = gather_evidence()
            report = analyze_with_ai(evidence)
            update_configmap(report)
        except Exception as e:
            logger.error(f"Fatal crash in polling loop: {e}")
        await asyncio.sleep(15)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(polling_loop())

@app.get("/aiops", response_class=HTMLResponse)
async def dashboard():
    report_data = "{}"
    try:
        cm = core_v1.read_namespaced_config_map(name=CONFIGMAP_NAME, namespace=AIOPS_NAMESPACE)
        if cm.data and "report.json" in cm.data:
            report_data = cm.data["report.json"]
    except: pass
    
    try:
        parsed_report = json.loads(report_data)
        formatted_json = json.dumps(parsed_report, indent=4)
        if parsed_report.get("status") == "healthy":
            status_color, text_color = "bg-green-500", "text-green-400"
        elif parsed_report.get("status") == "error":
            status_color, text_color = "bg-yellow-500", "text-yellow-400"
        else:
            status_color, text_color = "bg-red-500", "text-red-400"
    except:
        formatted_json = report_data
        status_color, text_color = "bg-gray-500", "text-gray-400"
    
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
        <div class="max-w-4xl mx-auto">
            <div class="flex flex-col md:flex-row items-start md:items-center justify-between mb-8 border-b border-gray-800 pb-6">
                <div>
                    <h1 class="text-3xl font-bold text-white tracking-tight">AIOps Telemetry Engine</h1>
                    <p class="text-sm text-gray-400 mt-1">Watching namespace: <span class="text-blue-400 font-mono">{WATCH_NAMESPACE}</span></p>
                </div>
                <div class="mt-4 md:mt-0 flex items-center space-x-3 bg-gray-900 px-4 py-2 rounded-full border border-gray-800">
                    <span class="relative flex h-3 w-3">
                      <span class="animate-ping absolute inline-flex h-full w-full rounded-full {status_color} opacity-75"></span>
                      <span class="relative inline-flex rounded-full h-3 w-3 {status_color}"></span>
                    </span>
                    <span class="text-sm font-medium text-gray-300">Live AI Polling</span>
                </div>
            </div>
            <div class="bg-gray-900 rounded-xl shadow-2xl border border-gray-800 overflow-hidden">
                <div class="bg-gray-800/50 px-6 py-4 border-b border-gray-800 flex justify-between items-center">
                    <h2 class="text-sm font-semibold text-gray-300 uppercase tracking-wider">Latest Azure OpenAI RCA Report</h2>
                    <span class="text-xs text-gray-500 font-mono bg-gray-950 px-2 py-1 rounded">Auto-refresh: 10s</span>
                </div>
                <div class="p-6 overflow-x-auto">
                    <pre class="text-sm font-mono {text_color} drop-shadow-md"><code>{formatted_json}</code></pre>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
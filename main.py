from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import httpx
import yaml
import json
import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import asyncio
from dotenv import load_dotenv
from openai import OpenAI
import uvicorn

app = FastAPI(title="CVEWB - CVE Workbench", version="0.1.0")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Cache directory
CACHE_DIR = "cache"
os.makedirs(CACHE_DIR, exist_ok=True)

# Models
class CVERequest(BaseModel):
    cve_id: str
    component: Optional[str] = None
    ai_analysis: bool = False

class AIConfig(BaseModel):
    provider: str = "chatgpt"  # "ollama" or "chatgpt"
    model_name: str = "gpt-4o-mini"
    api_key: Optional[str] = None
    ollama_url: str = "http://localhost:11434"

# Global configuration
ai_config = AIConfig()
system_context = {}

# Load system context at startup
async def load_system_context():
    global system_context
    try:
        with open("system_context.yaml", "r") as f:
            system_context = yaml.safe_load(f)
    except FileNotFoundError:
        system_context = {}

# Load environment variables and initialize config
def load_env_config():
    global ai_config
    # Load .env file if it exists
    load_dotenv()
    
    # Get OpenAI API key from environment
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        ai_config.api_key = openai_key
        print(f"🔑 INFO: Loaded OpenAI API key from .env file (ending with ...{openai_key[-4:]})")
    else:
        print("🔑 INFO: No OpenAI API key found in .env file")

@app.on_event("startup")
async def startup_event():
    load_env_config()
    await load_system_context()

# Cache management
def is_cache_valid(filepath: str, hours: int = 4) -> bool:
    if not os.path.exists(filepath):
        return False
    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
    return datetime.now() - file_time < timedelta(hours=hours)

# API clients
async def fetch_nvd_data(cve_id: str) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = await client.get(url)
        if response.status_code == 200:
            return response.json()
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

async def fetch_epss_data(cve_id: str) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = await client.get(url)
        if response.status_code == 200:
            return response.json()
        return {"data": []}

async def fetch_kev_data() -> Dict[str, Any]:
    cache_file = os.path.join(CACHE_DIR, "kev.json")
    
    if is_cache_valid(cache_file):
        with open(cache_file, "r") as f:
            return json.load(f)
    
    async with httpx.AsyncClient() as client:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            with open(cache_file, "w") as f:
                json.dump(data, f)
            return data
        return {"vulnerabilities": []}

async def fetch_github_advisories() -> List[Dict[str, Any]]:
    cache_file = os.path.join(CACHE_DIR, "github_advisories.json")
    
    if is_cache_valid(cache_file):
        with open(cache_file, "r") as f:
            return json.load(f)
    
    async with httpx.AsyncClient() as client:
        url = "https://api.github.com/advisories"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        response = await client.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            with open(cache_file, "w") as f:
                json.dump(data, f)
            return data
        return []

async def perform_ai_analysis(cve_data: Dict[str, Any], component_context: Optional[Dict[str, Any]] = None) -> Any:
    if ai_config.provider == "ollama":
        return await analyze_with_ollama(cve_data, component_context)
    elif ai_config.provider == "chatgpt":
        return await analyze_with_chatgpt(cve_data, component_context)
    return {"error": True, "message": "AI analysis not configured"}

async def analyze_with_ollama(cve_data: Dict[str, Any], component_context: Optional[Dict[str, Any]] = None) -> str:
    print(f"🤖 DEBUG: Starting AI analysis with Ollama")
    print(f"🤖 DEBUG: Ollama URL: {ai_config.ollama_url}")
    print(f"🤖 DEBUG: Model: {ai_config.model_name}")
    
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            prompt = create_analysis_prompt(cve_data, component_context)
            print(f"🤖 DEBUG: Generated prompt length: {len(prompt)} characters")
            
            # First, check if Ollama is running and the model exists
            print(f"🤖 DEBUG: Checking Ollama connection...")
            try:
                start_time = datetime.now()
                models_response = await client.get(f"{ai_config.ollama_url}/api/tags")
                check_time = (datetime.now() - start_time).total_seconds()
                print(f"🤖 DEBUG: Model check took {check_time:.2f} seconds")
                
                if models_response.status_code != 200:
                    print(f"🤖 DEBUG: Ollama returned status {models_response.status_code}")
                    return "Ollama service is not running. Please start Ollama first."
                
                models = models_response.json()
                available_models = [model.get("name", "") for model in models.get("models", [])]
                print(f"🤖 DEBUG: Available models: {available_models}")
                
                if ai_config.model_name not in available_models:
                    return f"Model '{ai_config.model_name}' not found. Available models: {', '.join(available_models) if available_models else 'None'}"
                
                print(f"🤖 DEBUG: Model '{ai_config.model_name}' found, proceeding with analysis...")
            
            except Exception as e:
                print(f"🤖 DEBUG: Connection check failed: {str(e)}")
                return f"Cannot connect to Ollama at {ai_config.ollama_url}. Please check if Ollama is running. Error: {str(e)}"
            
            # Generate analysis
            print(f"🤖 DEBUG: Sending analysis request to Ollama...")
            start_time = datetime.now()
            
            response = await client.post(
                f"{ai_config.ollama_url}/api/generate",
                json={
                    "model": ai_config.model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "top_p": 0.9
                    }
                },
                timeout=60.0
            )
            
            analysis_time = (datetime.now() - start_time).total_seconds()
            print(f"🤖 DEBUG: Analysis request completed in {analysis_time:.2f} seconds")
            print(f"🤖 DEBUG: Response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                response_text = result.get("response", "")
                print(f"🤖 DEBUG: Response length: {len(response_text)} characters")
                print(f"🤖 DEBUG: Analysis successful!")
                return response_text if response_text else "Analysis completed but no response received"
            else:
                print(f"🤖 DEBUG: Error response: {response.text}")
                return f"Ollama API error: HTTP {response.status_code} - {response.text}"
                
    except httpx.TimeoutException as e:
        print(f"🤖 DEBUG: Timeout occurred: {str(e)}")
        return "AI Analysis timeout. The analysis is taking longer than expected. Try with a smaller model or increase timeout."
    except httpx.ConnectError as e:
        print(f"🤖 DEBUG: Connection error: {str(e)}")
        return f"Cannot connect to Ollama at {ai_config.ollama_url}. Please ensure Ollama is running and accessible."
    except Exception as e:
        print(f"🤖 DEBUG: Unexpected error: {str(e)}")
        return f"AI Analysis error: {str(e)}"

async def analyze_with_chatgpt(cve_data: Dict[str, Any], component_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    print(f"🤖 DEBUG: Starting AI analysis with ChatGPT using OpenAI SDK")
    print(f"🤖 DEBUG: Model: {ai_config.model_name}")
    
    if not ai_config.api_key:
        print(f"🤖 DEBUG: ChatGPT API key not configured")
        return {
            "error": True,
            "message": "ChatGPT API key not configured. Please set your OpenAI API key in the configuration."
        }
    
    try:
        client = OpenAI(api_key=ai_config.api_key)
        prompt = create_analysis_prompt_json(cve_data, component_context)
        print(f"🤖 DEBUG: Generated prompt length: {len(prompt)} characters")
        
        print(f"🤖 DEBUG: Sending request to OpenAI API...")
        start_time = datetime.now()
        
        # Try the new responses API first, fallback to chat completions if needed
        try:
            # Use the responses API with web search if available
            response = client.responses.create(
                model=ai_config.model_name,
                tools=[{"type": "web_search"}],
                input=prompt
            )
            
            analysis_time = (datetime.now() - start_time).total_seconds()
            print(f"🤖 DEBUG: Responses API request completed in {analysis_time:.2f} seconds")
            
            # Extract the response content using output_text property
            if response and hasattr(response, 'output_text'):
                content = response.output_text
                print(f"🤖 DEBUG: Response length: {len(content)} characters")
                print(f"🤖 DEBUG: Analysis successful with responses API!")
                
                try:
                    # Try to parse as JSON
                    analysis_json = json.loads(content)
                    return analysis_json
                except json.JSONDecodeError:
                    # Fallback to text response if JSON parsing fails
                    return {
                        "error": False,
                        "summary": content[:200] + "..." if len(content) > 200 else content,
                        "vulnerability_type": "Unknown",
                        "severity": "Unknown", 
                        "exploitation_status": "Unknown",
                        "fixed_versions": [],
                        "risk_assessment": "Unable to parse structured response",
                        "raw_response": content
                    }
            else:
                print(f"🤖 DEBUG: Responses API returned unexpected structure, trying chat completions...")
                raise Exception("Responses API structure unexpected")
                
        except Exception as responses_error:
            print(f"🤖 DEBUG: Responses API failed: {str(responses_error)}, falling back to chat completions...")
            
            # Fallback to standard chat completions API
            response = client.chat.completions.create(
                model=ai_config.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in vulnerability analysis. Provide structured, actionable analysis based on the latest available information. Use your knowledge cutoff and reasoning to provide the best possible analysis."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            analysis_time = (datetime.now() - start_time).total_seconds()
            print(f"🤖 DEBUG: Chat completions request completed in {analysis_time:.2f} seconds")
            
            if response and response.choices and len(response.choices) > 0:
                content = response.choices[0].message.content
                print(f"🤖 DEBUG: Response length: {len(content)} characters")
                print(f"🤖 DEBUG: Analysis successful with chat completions!")
                
                try:
                    # Try to parse as JSON
                    analysis_json = json.loads(content)
                    return analysis_json
                except json.JSONDecodeError:
                    # Fallback to text response if JSON parsing fails
                    return {
                        "error": False,
                        "summary": content[:200] + "..." if len(content) > 200 else content,
                        "vulnerability_type": "Unknown",
                        "severity": "Unknown", 
                        "exploitation_status": "Unknown",
                        "fixed_versions": [],
                        "risk_assessment": "Unable to parse structured response - Chat completions used",
                        "raw_response": content
                    }
            else:
                return {
                    "error": True,
                    "message": "No response content received from OpenAI API"
                }
        
    except Exception as e:
        print(f"🤖 DEBUG: OpenAI SDK error: {str(e)}")
        print(f"🤖 DEBUG: Exception type: {type(e).__name__}")
        
        # Handle different types of OpenAI errors
        error_message = str(e)
        if "authentication" in error_message.lower():
            error_message = "Authentication failed. Please check your OpenAI API key."
        elif "rate limit" in error_message.lower():
            error_message = "Rate limit exceeded. Please wait and try again."
        elif "model" in error_message.lower() and "not found" in error_message.lower():
            error_message = f"Model '{ai_config.model_name}' not found or not accessible."
        
        return {
            "error": True,
            "message": f"ChatGPT Analysis error: {error_message}"
        }

def create_analysis_prompt_json(cve_data: Dict[str, Any], component_context: Optional[Dict[str, Any]] = None) -> str:
    # Extract CVE details for better prompt structure
    cve_id = cve_data.get("cve_id", "Unknown")
    nvd_data = cve_data.get("nvd", {})
    epss_data = cve_data.get("epss", {})
    kev_entry = cve_data.get("kev")
    
    # Extract key vulnerability information
    vulnerability_desc = ""
    cvss_score = "Unknown"
    severity = "Unknown"
    cvss_vector = ""
    
    if nvd_data and "vulnerabilities" in nvd_data:
        vuln_data = nvd_data["vulnerabilities"][0] if nvd_data["vulnerabilities"] else {}
        cve_details = vuln_data.get("cve", {})
        
        # Get description
        descriptions = cve_details.get("descriptions", [])
        if descriptions:
            vulnerability_desc = descriptions[0].get("value", "")
        
        # Get CVSS score and vector
        metrics = cve_details.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", "Unknown")
            severity = cvss_data.get("cvssData", {}).get("baseSeverity", "Unknown")
            cvss_vector = cvss_data.get("cvssData", {}).get("vectorString", "")
        elif "cvssMetricV3" in metrics:
            cvss_data = metrics["cvssMetricV3"][0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", "Unknown")
            severity = cvss_data.get("cvssData", {}).get("baseSeverity", "Unknown")
            cvss_vector = cvss_data.get("cvssData", {}).get("vectorString", "")
    
    # Get EPSS score
    epss_score = "Not available"
    if epss_data.get("data"):
        epss_score = epss_data["data"][0].get("epss", "Not available")
    
    # Build system context information
    environment_context = ""
    security_context = ""
    
    if component_context:
        environment_context = f"""
IMPORTANT: This analysis is for the "{component_context.get('name', 'Unknown')}" component in our environment:
{component_context.get('description', 'No description available')}
"""
    elif system_context and system_context.get("components"):
        environment_context = f"""
Our environment includes these components that might be affected:
{chr(10).join(f"- {comp.get('name')}: {comp.get('description', '')}" for comp in system_context["components"][:3])}
"""
    
    if system_context.get("security architecture"):
        security_context = f"""
Security Architecture Context:
{chr(10).join(f"- {item}" for item in system_context["security architecture"][:5])}
"""
    
    prompt = f"""Analyze {cve_id} and provide a structured JSON response for vulnerability assessment.

Use web search to find the latest information about:
- Current exploitation status and active attacks
- Available patches and fixed versions  
- Latest security advisories and vendor statements
- Real-world impact and exploitation difficulty

Available data:
- CVE: {cve_id}
- Description: {vulnerability_desc}
- CVSS Score: {cvss_score} ({severity})
- CVSS Vector: {cvss_vector}
- EPSS Score: {epss_score}
- Known Exploited: {'Yes' if kev_entry else 'No'}
{environment_context}
{security_context}

Return ONLY a valid JSON object with this exact structure:

{{
  "summary": "Brief 2-3 sentence high-level summary of the vulnerability and its significance",
  "vulnerability_type": "Type of vulnerability (e.g., 'Remote Code Execution', 'SQL Injection', 'Authentication Bypass')",
  "affected_software": "Name and description of affected software/product",
  "vulnerable_versions": "Range of vulnerable versions",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW based on CVSS and real-world impact",
  "cvss_score": {cvss_score if cvss_score != "Unknown" else "null"},
  "exploitation_status": "ACTIVELY_EXPLOITED|PROOF_OF_CONCEPT|NO_KNOWN_EXPLOITS",
  "attack_vector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
  "attack_complexity": "LOW|HIGH", 
  "fixed_versions": "Range of fixed versions or 'No patch available'",
  "risk_assessment": {{
    "immediate_threat": "HIGH|MEDIUM|LOW - assessment based on our environment context",
    "business_impact": "Brief description of potential business impact",
    "recommendation": "PATCH_IMMEDIATELY|PATCH_SOON|MONITOR|LOW_PRIORITY",
    "context_specific_risk": "Risk assessment specific to our infrastructure components"
  }},
  "mitigation_steps": [
    "Step 1: Specific action to take",
    "Step 2: Another specific action", 
    "Step 3: Verification steps"
  ]
}}

Focus on providing concise, actionable, up-to-date information. Use web search to get the latest exploitation status and patch information."""
    
    return prompt

def create_analysis_prompt(cve_data: Dict[str, Any], component_context: Optional[Dict[str, Any]] = None) -> str:
    # Extract CVE details for better prompt structure
    cve_id = cve_data.get("cve_id", "Unknown")
    nvd_data = cve_data.get("nvd", {})
    epss_data = cve_data.get("epss", {})
    kev_entry = cve_data.get("kev")
    
    # Extract key vulnerability information
    vulnerability_desc = ""
    cvss_score = "Unknown"
    severity = "Unknown"
    cvss_vector = ""
    
    if nvd_data and "vulnerabilities" in nvd_data:
        vuln_data = nvd_data["vulnerabilities"][0] if nvd_data["vulnerabilities"] else {}
        cve_details = vuln_data.get("cve", {})
        
        # Get description
        descriptions = cve_details.get("descriptions", [])
        if descriptions:
            vulnerability_desc = descriptions[0].get("value", "")
        
        # Get CVSS score and vector
        metrics = cve_details.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", "Unknown")
            severity = cvss_data.get("cvssData", {}).get("baseSeverity", "Unknown")
            cvss_vector = cvss_data.get("cvssData", {}).get("vectorString", "")
        elif "cvssMetricV3" in metrics:
            cvss_data = metrics["cvssMetricV3"][0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", "Unknown")
            severity = cvss_data.get("cvssData", {}).get("baseSeverity", "Unknown")
            cvss_vector = cvss_data.get("cvssData", {}).get("vectorString", "")
    
    # Get EPSS score
    epss_score = "Not available"
    if epss_data.get("data"):
        epss_score = epss_data["data"][0].get("epss", "Not available")
    
    # Build system context information
    environment_context = ""
    if component_context:
        environment_context = f"""
IMPORTANT: This analysis is for the "{component_context.get('name', 'Unknown')}" component in our environment:
{component_context.get('description', 'No description available')}
"""
    elif system_context and system_context.get("components"):
        environment_context = f"""
Our environment includes these components that might be affected:
{chr(10).join(f"- {comp.get('name')}: {comp.get('description', '')}" for comp in system_context["components"][:3])}
"""
    
    prompt = f"""Analyze {cve_id} and provide a practical, actionable breakdown similar to how a security expert would explain it to their team.

Available data:
- CVE: {cve_id}
- Description: {vulnerability_desc}
- CVSS Score: {cvss_score} ({severity})
- CVSS Vector: {cvss_vector}
- EPSS Score: {epss_score}
- Known Exploited: {'Yes' if kev_entry else 'No'}
{environment_context}

Structure your response like this:

## What is it

- **Affected software**: [Name the specific software/product and what it's used for]
- **Versions**: [List the vulnerable versions clearly - be specific]
- **Type of issue**: [Explain what kind of vulnerability this is in simple terms]
- **Severity**: [Mention the CVSS score and what it means practically]
- **Attack Vector**: [How can this be exploited - network, local, etc.]
- **Attack Complexity**: [How difficult is it to exploit]
- **Privileges Required**: [What access does an attacker need]
- **User Interaction**: [Does it need user action]

## What it means / risk

- [Explain in practical terms what an attacker could do if they exploit this]
- [Describe the potential business impact - data breach, service disruption, etc.]
- [Mention if this is being actively exploited in the wild]
- [Explain why this matters for infrastructure/applications that use this software]

## Mitigation / Fixes

- **Patched versions**: [List the specific fixed versions - this is critical information]
- **Upgrade instructions**: [Provide clear guidance on how to upgrade]
- **For cloud services**: [Mention if patches are automatic or need manual action]
- **For self-hosted**: [Explain what needs to be updated and how]
- **Workarounds**: [If patches aren't available, what temporary measures can be taken]
- **Verification**: [How to check if you're running a vulnerable version]

Focus on being practical and actionable. Don't use generic security advice - provide specific information about versions, patches, and real-world implications. Write like you're briefing a technical team that needs to make decisions quickly."""
    
    return prompt

# Routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    return templates.TemplateResponse("config.html", {"request": request})

@app.post("/api/analyze")
async def analyze_cve(request: CVERequest):
    try:
        # Fetch data from all sources
        nvd_data = await fetch_nvd_data(request.cve_id)
        epss_data = await fetch_epss_data(request.cve_id)
        kev_data = await fetch_kev_data()
        github_advisories = await fetch_github_advisories()
        
        # Find KEV entry
        kev_entry = next(
            (vuln for vuln in kev_data.get("vulnerabilities", []) 
             if vuln.get("cveID") == request.cve_id), None
        )
        
        # Find GitHub advisory
        github_entry = next(
            (advisory for advisory in github_advisories 
             if request.cve_id in [cve.get("number") for cve in advisory.get("cves", [])]), None
        )
        
        # Get component context if specified
        component_context = None
        if request.component and system_context:
            component_context = next(
                (comp for comp in system_context.get("components", []) 
                 if comp.get("name", "").lower() == request.component.lower()), None
            )
        
        # Compile analysis data
        analysis_data = {
            "cve_id": request.cve_id,
            "nvd": nvd_data,
            "epss": epss_data,
            "kev": kev_entry,
            "github": github_entry,
            "component": component_context,
            "ai_analysis": None
        }
        
        # Perform AI analysis if requested
        if request.ai_analysis:
            ai_result = await perform_ai_analysis(analysis_data, component_context)
            analysis_data["ai_analysis"] = ai_result
        
        return JSONResponse(content=analysis_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/config")
async def update_config(config: AIConfig):
    global ai_config
    ai_config = config
    return {"status": "success", "message": "Configuration updated"}

@app.get("/api/config")
async def get_config():
    # Include API key if it exists (masked for security in logs but full for frontend)
    config_dict = ai_config.model_dump()
    return config_dict

@app.get("/api/components")
async def get_components():
    return system_context.get("components", [])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

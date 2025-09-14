# CVEWB - CVE Workbench

**A completely free and open vulnerability management platform.**

CVEWB is an AI-assisted vulnerability analysis workbench that aggregates critical security information into a single pane of glass. It provides context-aware vulnerability assessment by combining multiple authoritative data sources with intelligent analysis tailored to your specific organizational infrastructure.

![CVEWB Interface](https://img.shields.io/badge/Status-Active%20Development-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-green)
![License](https://img.shields.io/badge/License-MIT-blue)

## 🎯 The Problem

Enterprise vulnerability management tools are expensive and often overkill for smaller organizations. Security teams need:
- **Context-aware analysis** - How does this CVE actually affect *our* infrastructure?
- **Actionable intelligence** - What should we do about it, and how urgent is it?
- **Comprehensive data** - CVSS scores, EPSS probabilities, KEV status, and vendor advisories in one place
- **AI-powered insights** - Intelligent risk assessment based on organizational context

## 💡 The Solution

CVEWB provides:
- **Single Pane of Glass** - All vulnerability data aggregated from authoritative sources
- **AI-Assisted Workflow** - Intelligent analysis using your organizational context
- **Context-Aware Assessment** - Risk evaluation based on your actual infrastructure components
- **Cost-Effective** - Self-hosted, open-source alternative to expensive enterprise platforms

## 🚀 Key Features

### Data Sources Integration
- **NIST NVD** - Official CVE data, CVSS scores, and vulnerability details
- **EPSS** - Exploitation Prediction Scoring System for likelihood assessment
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **GitHub Advisories** - Community-driven security advisories

### AI-Powered Analysis
- **OpenAI Integration** - GPT-4 powered analysis with web search capabilities
- **Local AI Support** - Ollama integration for on-premises AI models
- **Context-Aware Prompting** - Analysis tailored to your infrastructure components
- **Structured Output** - JSON-formatted analysis for consistent processing

### Organizational Context
- **System Components** - Define your infrastructure stack via `system_context.yaml`
- **Security Architecture** - Include your security controls and environment details
- **Risk Contextualization** - AI assessment considers your specific environment

## 📋 Workflow

1. **CVE Input** - User provides CVE identifier (e.g., `CVE-2024-12345`)
2. **Component Context** (Optional) - Select relevant system component
3. **Data Aggregation** - Automatic collection from all data sources:
   - NVD vulnerability details and CVSS scoring
   - EPSS exploitation probability
   - CISA KEV status check
   - GitHub security advisories
4. **AI Analysis** (Optional) - Intelligent risk assessment including:
   - Vulnerability impact analysis
   - Exploitation likelihood
   - Patch availability and upgrade paths
   - Context-specific risk evaluation
   - Actionable mitigation steps

## 🛠️ Quick Start

### Prerequisites
- Python 3.13+
- UV package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- OpenAI API key (for AI analysis) or Ollama (for local AI)

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/cvewb.git
cd cvewb

# Install dependencies
uv sync

# Set up environment
cp .env.example .env
# Edit .env and add your OpenAI API key if using ChatGPT
```

### Configuration

1. **AI Configuration** - Visit `/config` to set up:
   - **OpenAI/ChatGPT** - Requires API key, provides web search capabilities
   - **Ollama** - Local AI models, privacy-focused, no external dependencies

2. **System Context** - Edit `system_context.yaml` to define your infrastructure:
   ```yaml
   components:
     - name: "Frontend Applications"
       description: "React.js applications served via CDN"
     - name: "API Services"
       description: "Go-based microservices on Kubernetes"
     - name: "Database Systems"
       description: "PostgreSQL and Redis clusters"
   
   security_architecture:
     - "Zero-trust network with VPC isolation"
     - "WAF protection for public endpoints"
     - "Container scanning in CI/CD pipeline"
   ```

### Running

```bash
# Development server
uv run main.app

# Access the application
open http://localhost:8000
```

## 🔄 Usage Example

1. Navigate to `http://localhost:8000`
2. Enter CVE ID: `CVE-2024-3094` (XZ backdoor)
3. Select component: "API Services" (optional)
4. Enable AI Analysis
5. Click "Start Analysis"

**Result**: Comprehensive vulnerability assessment including CVSS 10.0 score, active exploitation status, immediate patch recommendations, and context-specific risk for your API infrastructure.


## 🔮 Planned Enhancements

### Immediate Roadmap
- **Enhanced Information Display** - Improved UI/UX for analysis results
- **Workflow Improvements** - Streamlined analysis process
- **Docker Container** - Easy deployment and scaling
- **HITL Analysis** - Human-in-the-loop analysis refinement
- **Analysis Persistence** - Save and manage completed analyses

### Future Features
- **Artifact Generation** - Export analysis reports for:
  - Compliance evidence (SOC2, ISO 27001)
  - Audit documentation
  - Vanta integration
  - Management reporting
- **Batch Processing** - Analyze multiple CVEs simultaneously
- **Integration APIs** - Connect with existing security tools
- **Custom Scoring** - Organization-specific risk scoring models
- **Historical Tracking** - Vulnerability timeline and remediation tracking

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   FastAPI        │    │   Data Sources  │
│   (HTML/JS)     │───▶│   Backend        │───▶│   - NVD         │
│                 │    │                  │    │   - EPSS        │
└─────────────────┘    └──────────────────┘    │   - CISA KEV    │
                              │                │   - GitHub      │
                              ▼                └─────────────────┘
                       ┌──────────────────┐    
                       │   AI Providers   │    
                       │   - OpenAI       │    
                       │   - Ollama       │    
                       └──────────────────┘    
```

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests to the `main` branch.

### Development Setup
```bash
# Install development dependencies
uv sync --dev

# Run tests
uv run pytest

# Code formatting
uv run ruff format
uv run ruff check --fix
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST NVD** - National Vulnerability Database
- **FIRST.org** - EPSS scoring system
- **CISA** - Known Exploited Vulnerabilities catalog
- **GitHub** - Security Advisory database

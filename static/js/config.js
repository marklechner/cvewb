// Configuration page JavaScript
document.addEventListener('DOMContentLoaded', function() {
    initializeConfigPage();
    setupEventListeners();
    loadCurrentConfig();
    loadSystemComponents();
});

function initializeConfigPage() {
    // Load API key from session storage if exists
    const apiKey = sessionStorage.getItem('openai_api_key');
    if (apiKey) {
        document.getElementById('apiKey').value = apiKey;
    }
}

function setupEventListeners() {
    const aiConfigForm = document.getElementById('aiConfigForm');
    const providerRadios = document.querySelectorAll('input[name="provider"]');
    const testOllamaBtn = document.getElementById('testOllamaBtn');
    const testChatGPTBtn = document.getElementById('testChatGPTBtn');
    const resetConfigBtn = document.getElementById('resetConfigBtn');
    const editContextBtn = document.getElementById('editContextBtn');

    // Form submission
    aiConfigForm.addEventListener('submit', handleConfigSubmit);

    // Provider selection
    providerRadios.forEach(radio => {
        radio.addEventListener('change', handleProviderChange);
    });

    // Test buttons
    testOllamaBtn.addEventListener('click', testOllamaConnection);
    testChatGPTBtn.addEventListener('click', testChatGPTConnection);

    // Reset button
    resetConfigBtn.addEventListener('click', resetToDefaults);

    // Edit context button
    editContextBtn.addEventListener('click', openContextModal);

    // API key session storage
    const apiKeyInput = document.getElementById('apiKey');
    apiKeyInput.addEventListener('input', function() {
        if (this.value) {
            sessionStorage.setItem('openai_api_key', this.value);
        } else {
            sessionStorage.removeItem('openai_api_key');
        }
    });
}

async function loadCurrentConfig() {
    try {
        const response = await fetch('/api/config');
        const config = await response.json();

        // Update form with current config
        document.querySelector(`input[name="provider"][value="${config.provider}"]`).checked = true;
        document.getElementById('ollamaUrl').value = config.ollama_url;
        document.getElementById('modelName').value = config.model_name;

        // Handle API key - prioritize session storage, then backend config
        const sessionApiKey = sessionStorage.getItem('openai_api_key');
        const apiKeyField = document.getElementById('apiKey');
        
        if (sessionApiKey) {
            // Use session storage key if available (user manually entered)
            apiKeyField.value = sessionApiKey;
        } else if (config.api_key) {
            // Use backend key (from .env) if no session storage key
            apiKeyField.value = config.api_key;
            // Store in session storage for consistency
            sessionStorage.setItem('openai_api_key', config.api_key);
            
            // Show status message if key was loaded from .env
            showStatusMessage('OpenAI API key loaded from environment (.env file)', 'info');
        }

        // Handle provider-specific display
        handleProviderChange({ target: document.querySelector(`input[name="provider"][value="${config.provider}"]`) });

    } catch (error) {
        console.error('Failed to load current configuration:', error);
        showStatusMessage('Failed to load current configuration', 'error');
    }
}

async function loadSystemComponents() {
    try {
        const response = await fetch('/api/components');
        const components = await response.json();

        const componentsDisplay = document.getElementById('componentsDisplay');
        componentsDisplay.innerHTML = '';

        if (components.length === 0) {
            componentsDisplay.innerHTML = `
                <div class="no-components">
                    <i class="fas fa-info-circle"></i>
                    <p>No system components configured. Edit the system_context.yaml file to add components.</p>
                </div>
            `;
            return;
        }

        components.forEach(component => {
            const componentCard = document.createElement('div');
            componentCard.className = 'component-card';
            componentCard.innerHTML = `
                <div class="component-header">
                    <h4>${component.name}</h4>
                </div>
                <div class="component-body">
                    <p>${component.description}</p>
                </div>
            `;
            componentsDisplay.appendChild(componentCard);
        });

    } catch (error) {
        console.error('Failed to load system components:', error);
        const componentsDisplay = document.getElementById('componentsDisplay');
        componentsDisplay.innerHTML = `
            <div class="error-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>Failed to load system components</p>
            </div>
        `;
    }
}

function handleProviderChange(event) {
    const selectedProvider = event.target.value;
    const ollamaConfig = document.getElementById('ollamaConfig');
    const chatgptConfig = document.getElementById('chatgptConfig');

    if (selectedProvider === 'ollama') {
        ollamaConfig.style.display = 'block';
        chatgptConfig.style.display = 'none';
    } else if (selectedProvider === 'chatgpt') {
        ollamaConfig.style.display = 'none';
        chatgptConfig.style.display = 'block';
    }
}

async function handleConfigSubmit(event) {
    event.preventDefault();

    const formData = new FormData(event.target);
    const config = {
        provider: formData.get('provider'),
        ollama_url: formData.get('ollama_url'),
        model_name: formData.get('model_name'),
        api_key: formData.get('api_key')
    };

    try {
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });

        if (response.ok) {
            const result = await response.json();
            showStatusMessage('Configuration saved successfully', 'success');
            
            // Store API key in session storage if provided
            if (config.api_key) {
                sessionStorage.setItem('openai_api_key', config.api_key);
            }
        } else {
            throw new Error('Failed to save configuration');
        }

    } catch (error) {
        console.error('Failed to save configuration:', error);
        showStatusMessage('Failed to save configuration', 'error');
    }
}

async function testOllamaConnection() {
    const testBtn = document.getElementById('testOllamaBtn');
    const statusIndicator = document.getElementById('ollamaStatus');
    const ollamaUrl = document.getElementById('ollamaUrl').value;
    const modelName = document.getElementById('modelName').value;

    setTestingState(testBtn, statusIndicator, 'Testing connection...');

    try {
        // Test Ollama connection by trying to list models or ping
        const response = await fetch(ollamaUrl + '/api/tags', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            const models = await response.json();
            const hasModel = models.models?.some(model => model.name === modelName);
            
            if (hasModel) {
                setSuccessState(statusIndicator, `Connected! Model "${modelName}" is available.`);
            } else {
                setWarningState(statusIndicator, `Connected, but model "${modelName}" not found. Available models: ${models.models?.map(m => m.name).join(', ') || 'None'}`);
            }
        } else {
            throw new Error(`HTTP ${response.status}`);
        }

    } catch (error) {
        console.error('Ollama connection test failed:', error);
        setErrorState(statusIndicator, `Connection failed: ${error.message}. Make sure Ollama is running.`);
    } finally {
        resetTestingState(testBtn, 'Test Connection');
    }
}

async function testChatGPTConnection() {
    const testBtn = document.getElementById('testChatGPTBtn');
    const statusIndicator = document.getElementById('chatgptStatus');
    const apiKey = document.getElementById('apiKey').value;

    if (!apiKey) {
        setErrorState(statusIndicator, 'Please enter an API key first.');
        return;
    }

    setTestingState(testBtn, statusIndicator, 'Testing API key...');

    try {
        // Test ChatGPT API with a simple request
        const response = await fetch('https://api.openai.com/v1/models', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.ok) {
            setSuccessState(statusIndicator, 'API key is valid and working!');
        } else if (response.status === 401) {
            setErrorState(statusIndicator, 'Invalid API key. Please check your key.');
        } else {
            throw new Error(`HTTP ${response.status}`);
        }

    } catch (error) {
        console.error('ChatGPT API test failed:', error);
        setErrorState(statusIndicator, `API test failed: ${error.message}`);
    } finally {
        resetTestingState(testBtn, 'Test API Key');
    }
}

function resetToDefaults() {
    // Reset form to default values
    document.querySelector('input[name="provider"][value="ollama"]').checked = true;
    document.getElementById('ollamaUrl').value = 'http://localhost:11434';
    document.getElementById('modelName').value = 'llama3.1-128k:latest';
    document.getElementById('apiKey').value = '';

    // Clear session storage
    sessionStorage.removeItem('openai_api_key');

    // Show correct provider config
    handleProviderChange({ target: document.querySelector('input[name="provider"][value="ollama"]') });

    // Clear status indicators
    clearStatusIndicator('ollamaStatus');
    clearStatusIndicator('chatgptStatus');

    showStatusMessage('Configuration reset to defaults', 'info');
}

function openContextModal() {
    const modal = document.getElementById('contextModal');
    const yamlContent = document.getElementById('yamlContent');
    
    // Load current system context YAML
    fetch('/system_context.yaml')
        .then(response => response.text())
        .then(yaml => {
            yamlContent.textContent = yaml;
        })
        .catch(error => {
            yamlContent.textContent = 'Error loading system_context.yaml file';
        });
    
    modal.style.display = 'block';
}

function closeContextModal() {
    const modal = document.getElementById('contextModal');
    modal.style.display = 'none';
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const toggle = input.parentNode.querySelector('.password-toggle i');
    
    if (input.type === 'password') {
        input.type = 'text';
        toggle.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        toggle.className = 'fas fa-eye';
    }
}

// Status indicator helper functions
function setTestingState(button, indicator, message) {
    button.disabled = true;
    button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Testing...`;
    indicator.className = 'status-indicator testing';
    indicator.textContent = message;
}

function resetTestingState(button, originalText) {
    button.disabled = false;
    button.innerHTML = `<i class="fas fa-plug"></i> ${originalText}`;
}

function setSuccessState(indicator, message) {
    indicator.className = 'status-indicator success';
    indicator.innerHTML = `<i class="fas fa-check"></i> ${message}`;
}

function setErrorState(indicator, message) {
    indicator.className = 'status-indicator error';
    indicator.innerHTML = `<i class="fas fa-times"></i> ${message}`;
}

function setWarningState(indicator, message) {
    indicator.className = 'status-indicator warning';
    indicator.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
}

function clearStatusIndicator(indicatorId) {
    const indicator = document.getElementById(indicatorId);
    indicator.className = 'status-indicator';
    indicator.textContent = '';
}

function showStatusMessage(message, type) {
    const statusMessage = document.getElementById('statusMessage');
    const messageText = statusMessage.querySelector('.message-text');
    const messageIcon = statusMessage.querySelector('.message-icon');
    
    // Set icon based on type
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    messageIcon.className = `message-icon ${icons[type] || icons.info}`;
    messageText.textContent = message;
    statusMessage.className = `status-message ${type}`;
    statusMessage.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        statusMessage.style.display = 'none';
    }, 5000);
}

// Modal click outside to close
window.onclick = function(event) {
    const modal = document.getElementById('contextModal');
    if (event.target === modal) {
        closeContextModal();
    }
};

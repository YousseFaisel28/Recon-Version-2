/**
 * ReconX AI Assistant Frontend Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    loadScanHistory();
});

const scanSelect = document.getElementById('scan-select');
const chatSection = document.getElementById('chat-section');
const chatWindow = document.getElementById('chat-window');
const selectedDomainSpan = document.getElementById('selected-domain');
const userInput = document.getElementById('user-input');
const sendBtn = document.getElementById('send-btn');

let currentReportId = '';

// 1. Load Scan History
async function loadScanHistory() {
    try {
        const resp = await fetch('/get_history');
        if (resp.status === 401) {
            window.location.href = '/login';
            return;
        }

        const data = await resp.json();
        const history = data.history || [];

        if (history.length === 0) {
            const opt = document.createElement('option');
            opt.textContent = "No scans found. Perform a scan first.";
            scanSelect.appendChild(opt);
            return;
        }

        history.forEach(scan => {
            const opt = document.createElement('option');
            opt.value = scan.report_id;
            const dateStr = new Date(scan.scanned_at).toLocaleDateString();
            opt.textContent = `${scan.domain} — ${dateStr}`;
            scanSelect.appendChild(opt);
        });

        if (scanSelect.value) {
            currentReportId = scanSelect.value;
            selectedDomainSpan.textContent = scanSelect.options[scanSelect.selectedIndex].text.split(' — ')[0];
            chatSection.classList.remove('hidden');
            chatSection.classList.add('flex');
            document.getElementById('ai-empty-state')?.classList.add('hidden');
            
            chatWindow.innerHTML = `
                <div class="message ai-message">
                    <div class="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white flex-shrink-0">
                      <i class="ph-bold ph-robot"></i>
                    </div>
                    <div class="msg-bubble">I've loaded the results for <strong>${selectedDomainSpan.textContent}</strong>. What would you like to know? You can click the quick questions above or type your own.</div>
                </div>
            `;
        }

    } catch (err) {
        console.error("Failed to load scan history:", err);
    }
}

// 2. Handle Selection Change (already handled cleanly in inline HTML script, but fallback here)
scanSelect.addEventListener('change', (e) => {
    const reportId = e.target.value;
    if (reportId) {
        currentReportId = reportId;
        chatSection.classList.remove('hidden');
        chatSection.classList.add('flex');
        document.getElementById('ai-empty-state')?.classList.add('hidden');

        // Update domain info
        const text = e.target.options[e.target.selectedIndex].text;
        selectedDomainSpan.textContent = text.split(' — ')[0];

        // Reset chat
        chatWindow.innerHTML = `
            <div class="message ai-message">
                <div class="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white flex-shrink-0">
                  <i class="ph-bold ph-robot"></i>
                </div>
                <div class="msg-bubble">I've loaded the results for <strong>${selectedDomainSpan.textContent}</strong>. What would you like to know? You can click the quick questions above or type your own.</div>
            </div>
        `;
    } else {
        chatSection.classList.add('hidden');
        chatSection.classList.remove('flex');
        document.getElementById('ai-empty-state')?.classList.remove('hidden');
        currentReportId = '';
    }
});

// 3. AI Interaction Functions
async function askAI(type) {
    if (!currentReportId) return;

    let endpoint = '';
    let userMsg = '';

    if (type === 'summarize') {
        endpoint = '/api/ai/summarize';
        userMsg = "Summarize the report";
    } else if (type === 'score') {
        endpoint = '/api/ai/score';
        userMsg = "Rate website security";
    } else if (type === 'prioritize') {
        endpoint = '/api/ai/prioritize';
        userMsg = "What should we fix first?";
    } else if (type === 'biggest_risk') {
        endpoint = '/api/ai/biggest_risk';
        userMsg = "Explain the biggest security risk";
    }

    addMessage(userMsg, 'user');

    // Show typing indicator
    const typingId = showTyping();

    try {
        const resp = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ report_id: currentReportId })
        });

        const data = await resp.json();
        removeTyping(typingId);

        if (data.answer) {
            addMessage(data.answer, 'ai');
        } else if (data.error) {
            addMessage(`Error: ${data.error}`, 'ai');
        } else {
            addMessage("I'm sorry, I encountered an error. Please try again.", 'ai');
        }

    } catch (err) {
        removeTyping(typingId);
        addMessage("Connection error while talking to AI.", 'ai');
    }
}

async function askCustom() {
    const question = userInput.value.trim();
    if (!question || !currentReportId) return;

    userInput.value = '';
    addMessage(question, 'user');

    const typingId = showTyping();

    try {
        const resp = await fetch('/api/ai/ask', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                report_id: currentReportId,
                question: question
            })
        });

        const data = await resp.json();
        removeTyping(typingId);

        if (data.answer) {
            addMessage(data.answer, 'ai');
        } else if (data.error) {
            addMessage(`Error: ${data.error}`, 'ai');
        } else {
            addMessage("I'm having trouble analyzing that specifically. Try asking about PHP, ports, or subdomains.", 'ai');
        }

    } catch (err) {
        removeTyping(typingId);
        addMessage("Connection error while talking to AI.", 'ai');
    }
}

// 4. Utility Functions
function addMessage(text, sender) {
    const div = document.createElement('div');
    div.className = `message ${sender}-message`;

    if (sender === 'user') {
        div.innerHTML = `<div class="msg-bubble">${escapeHtml(text)}</div>`;
    } else {
        // Parse markdown text so lists and formatting work correctly
        let parsedText = text;
        if (typeof marked !== 'undefined') {
            parsedText = marked.parse(text);
        } else {
            parsedText = text.includes('<') ? text : escapeHtml(text).replace(/\\n/g, '<br>');
        }

        div.innerHTML = `
            <div class="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white flex-shrink-0">
                <i class="ph-bold ph-robot"></i>
            </div>
            <div class="msg-bubble ai-markdown-content relative break-words dark:text-gray-200">${parsedText}</div>
        `;
    }

    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

function escapeHtml(unsafe) {
    return (unsafe || "").toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

function showTyping() {
    const id = 'typing-' + Date.now();
    const div = document.createElement('div');
    div.id = id;
    div.className = 'message ai-message';
    div.innerHTML = `
        <div class="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white flex-shrink-0">
            <i class="ph-bold ph-robot"></i>
        </div>
        <div class="msg-bubble flex items-center gap-2 text-gray-400">
            AI is thinking <i class="ph ph-spinner-gap animate-spin"></i>
        </div>
    `;
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;

    userInput.disabled = true;
    sendBtn.disabled = true;

    return id;
}

function removeTyping(id) {
    const el = document.getElementById(id);
    if (el) el.remove();

    userInput.disabled = false;
    sendBtn.disabled = false;
    userInput.focus();
}

function handleKey(e) {
    if (e.key === 'Enter') {
        askCustom();
    }
}

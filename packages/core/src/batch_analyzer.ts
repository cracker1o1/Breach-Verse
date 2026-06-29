import { PrismaClient } from '@prisma/client';
import * as readline from 'readline';
import * as path from 'path';
import { EnterprisePipelineCoordinator } from './services/enterpriseEngines';
import { ReportingEngine } from './services/reportingEngine';
import { ProviderSessionState, Finding } from './types/platform';

const prisma = new PrismaClient();

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const MAGENTA = '\x1b[35m';
const CYAN = '\x1b[36m';
const WHITE = '\x1b[37m';

const BG_RED = '\x1b[41m';

function colorizeMarkdownResponse(text: string): string {
  return text
    .split('\n')
    .map(line => {
      if (line.startsWith('# ') || line.startsWith('=== ')) return `${BOLD}${MAGENTA}${line.toUpperCase()}${RESET}`;
      if (line.startsWith('## ')) return `\n${BOLD}${CYAN}${line}${RESET}`;
      if (line.startsWith('### ')) return `${BOLD}${BLUE}${line}${RESET}`;
      
      let updatedLine = line;
      if (updatedLine.includes('[CONFIRMED]')) {
        updatedLine = updatedLine.replace('[CONFIRMED]', `${BG_RED}${BOLD}${WHITE}[CONFIRMED]${RESET}`);
      }
      if (updatedLine.includes('[LIKELY]')) {
        updatedLine = updatedLine.replace('[LIKELY]', `${BOLD}${YELLOW}[LIKELY]${RESET}`);
      }
      if (updatedLine.includes('[POSSIBLE]')) {
        updatedLine = updatedLine.replace('[POSSIBLE]', `${BOLD}${BLUE}[POSSIBLE]${RESET}`);
      }
      return updatedLine;
    })
    .join('\n');
}

async function launchAnalyzerConsole() {
  const latestAssessment = await prisma.assessment.findFirst({
    orderBy: { createdAt: 'desc' },
    include: { 
      endpoints: true, scripts: true, functions: true, taintFlows: true, 
      cryptoOperations: true, runtimeTaintFlows: true, domArtifacts: true, 
      browserStates: true, executionGraphs: true
    }
  });

  if (!latestAssessment) {
    console.error(`\n${RED}${BOLD}❌ ABORT: No baseline database logs located.${RESET}\n`);
    return;
  }

  console.log(`\n[*] Executing local modular enterprise data pipeline algorithms...`);
  const scriptInputs = latestAssessment.scripts.map(s => ({ url: s.url, content: s.rawContent }));
  const pipelineCoordinator = new EnterprisePipelineCoordinator();
  const generatedPipelineFindings = await pipelineCoordinator.runOrchestration(scriptInputs);

  const activeSessionState: ProviderSessionState = {
    conversationHistory: [],
    sessionMemory: {},
    runtimeTelemetry: [],
    collectedFindings: generatedPipelineFindings,
    assessmentContext: { targetUrl: latestAssessment.targetUrl, assessmentId: latestAssessment.id }
  };

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  console.log(`\n${CYAN}======================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}🔥 ENTERPRISE CLIENT-SIDE MULTI-PROVIDER GRAPH INTERACTIVE ENGINE${RESET}`);
  console.log(`======================================================================${RESET}`);
  console.log(`${BOLD}Target Assessment Scope Domain :${RESET} ${YELLOW}${activeSessionState.assessmentContext.targetUrl}${RESET}`);
  console.log(`${BOLD}Enterprise Processed Findings  :${RESET} ${GREEN}${activeSessionState.collectedFindings.length} Items Loaded${RESET}`);
  console.log(`${CYAN}----------------------------------------------------------------------${RESET}`);
  
  let selectedProviderNode = '1';

  const displayProviderSelectionGrid = () => {
    console.log(`\n${BOLD}${WHITE}Select Active Security Intelligence Provider Node:${RESET}`);
    console.log(` [1] ${BOLD}${CYAN}Google Gemini 2.5 Pro Core (Massive Context 🔥)${RESET}`);
    console.log(` [2] ${BOLD}${GREEN}Groq Cloud Infrastructure Grid (Llama 3.3 Strict Bound ⚡)${RESET}`);
    console.log(` [3] ${BOLD}${MAGENTA}Mistral Large Infrastructure AI Core${RESET}`);
    console.log(` [4] ${BOLD}${BLUE}Cohere Command-R Plus Enterprise Cluster${RESET}`);
    console.log(` [5] ${BOLD}${YELLOW}Export Generated Enterprise Reports to Disk Storage Paths${RESET}`);
    console.log(`${CYAN}----------------------------------------------------------------------${RESET}`);
  };

  const executeReportingExportSequence = () => {
    console.log(`\n[*] Dumping compiled enterprise report formats out-of-band to disk storage...`);
    const rootPath = process.cwd();
    
    ReportingEngine.exportToJSON(path.join(rootPath, 'security_report.json'), activeSessionState.collectedFindings);
    ReportingEngine.exportToJSONL(path.join(rootPath, 'security_report.jsonl'), activeSessionState.collectedFindings);
    ReportingEngine.exportToCSV(path.join(rootPath, 'security_report.csv'), activeSessionState.collectedFindings);
    ReportingEngine.exportToMarkdown(path.join(rootPath, 'security_report.md'), activeSessionState.collectedFindings, activeSessionState.assessmentContext.targetUrl);
    ReportingEngine.exportToHTML(path.join(rootPath, 'security_report.html'), activeSessionState.collectedFindings, activeSessionState.assessmentContext.targetUrl);

    console.log(`[${GREEN}✔${RESET}] Clean JSON, JSONL, CSV, Markdown, and HTML templates exported to root directory.`);
  };

  const runConversationalLoopChannel = () => {
    displayProviderSelectionGrid();
    
    rl.question(`\n${BOLD}${WHITE}⚙ Select Provider Target Node or Action (1-5): ${RESET}`, async (choice) => {
      const inputNode = choice.trim();
      
      if (inputNode === '5') {
        executeReportingExportSequence();
        runConversationalLoopChannel();
        return;
      }

      if (['1', '2', '3', '4'].includes(inputNode)) {
        selectedProviderNode = inputNode;
        const providerNames = { '1': 'Google Gemini', '2': 'Groq Cloud', '3': 'Mistral Core', '4': 'Cohere Cluster' };
        console.log(`\n[${GREEN}✔${RESET}] Switched channel connection node to: ${BOLD}${GREEN}${providerNames[selectedProviderNode as keyof typeof providerNames]}${RESET}`);
        startInteractiveChatShell();
        return;
      }

      console.error(`${RED}Invalid selection index. Choose 1-5.${RESET}`);
      runConversationalLoopChannel();
    });
  };

  const startInteractiveChatShell = () => {
    console.log(`\n${BOLD}${GREEN}💬 Conversational shell active. Type your technical question or type '${RED}switch${GREEN}' to swap provider nodes.${RESET}`);
    
    const askQuestion = () => {
      rl.question(`\n${BOLD}${CYAN}🔬 Ask AI (${selectedProviderNode === '1' ? 'Gemini' : selectedProviderNode === '2' ? 'Groq' : selectedProviderNode === '3' ? 'Mistral' : 'Cohere'}) > ${RESET}`, async (userInput) => {
        const query = userInput.trim();

        if (query.toLowerCase() === 'exit') {
          rl.close();
          return;
        }

        if (query.toLowerCase() === 'switch') {
          runConversationalLoopChannel();
          return;
        }

        if (!query) { askQuestion(); return; }

        console.log(`[*] Submitting prioritized telemetry graph payloads across provider channels...`);

        // ✅ OPTIMIZED: Adjusted allocation budget layout to avoid overloading Mistral/Groq pipelines
        let budget = { findings: 20, crypto: 15, taint: 15, runtime: 15, dom: 5, states: 2, graphs: 10, scripts: 5 };
        
        if (selectedProviderNode === '1') {
          budget = { findings: 400, crypto: 300, taint: 300, runtime: 400, dom: 150, states: 20, graphs: 200, scripts: 40 };
        } else if (selectedProviderNode === '3' || selectedProviderNode === '4') {
          budget = { findings: 50, crypto: 35, taint: 35, runtime: 40, dom: 15, states: 5, graphs: 30, scripts: 10 };
        }

        // Severity and security ranking prioritization filters
        const prioritizedFindings = [...activeSessionState.collectedFindings].sort((a, b) => {
          const weights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };
          return (weights[b.severity] || 0) - (weights[a.severity] || 0);
        }).slice(0, budget.findings);

        const prioritizedEndpoints = [...latestAssessment.endpoints].sort((a, b) => {
          const highRiskPattern = /auth|login|api|v1|v2|token|credential|pay/i;
          const bMatch = highRiskPattern.test(b.url) ? 1 : 0;
          const aMatch = highRiskPattern.test(a.url) ? 1 : 0;
          if (bMatch !== aMatch) return bMatch - aMatch;
          return b.method.localeCompare(a.method);
        }).slice(0, budget.findings);

        const prioritizedCrypto = [...latestAssessment.cryptoOperations].sort((a, b) => {
          const highRiskCrypto = /aes|rsa|gcm|cbc|encrypt|decrypt/i;
          const bMatch = highRiskCrypto.test(b.type + b.mode) ? 1 : 0;
          const aMatch = highRiskCrypto.test(a.type + a.mode) ? 1 : 0;
          return bMatch - aMatch;
        }).slice(0, budget.crypto);

        const prioritizedRuntime = [...latestAssessment.runtimeTaintFlows].sort((a, b) => {
          const highRiskLayers: Record<string, number> = { FORMDATA_APPEND: 3, DOM_TAINT: 2, FETCH_INTERCEPT: 1 };
          return (highRiskLayers[b.sourceType] || 0) - (highRiskLayers[a.sourceType] || 0);
        }).slice(0, budget.runtime);

        const analysisBlueprintPayload = `
=== MASTER CONTEXT AUTOMATION BLUEPRINT GRAPH ===
Target App Domain Domain Scope: ${activeSessionState.assessmentContext.targetUrl}

=== PRIORITIZED APPLICATION SOURCE SCRIPTS INVENTORY ===
${latestAssessment.scripts.slice(0, budget.scripts).map(s => `[FILE_NODE] URL: ${s.url} | Content Type: ${s.type} | Size: ${s.rawContent?.length || 0} bytes`).join('\n')}

=== CRITICAL SECURITY FINDINGS TREE (SORTED BY SEVERITY) ===
${prioritizedFindings.map((f, idx) => `[F-${idx + 1}] Title: ${f.title} | Type: ${f.type} | File: ${f.location.filePath} | Raw Context Data: ${f.raw}`).join('\n')}

=== RECONNAISSANCE ROUTER ENDPOINTS MATRIX (HIGH RISK FIRST) ===
${prioritizedEndpoints.map(e => `[ENDPOINT] Method: ${e.method} | URL Link Path Target: ${e.url} | File Mapping Node: ${e.sourceFile}`).join('\n')}

=== CAPTURED CRYPTOGRAPHIC CORE OPERATIONS (ENCRYPTION LOGICS) ===
${prioritizedCrypto.map(c => `[CRYPTO_ENGINE_LOGIC] Cipher Type: ${c.type} | Operational Mode: ${c.mode} | Key Source: ${c.keySource} | IV Structure: ${c.ivSource} | Outbound Destination Sink: ${c.destination} | Source Scope Target Chunk: ${c.sourceFile}`).join('\n')}

=== STATIC SOURCE-TO-SINK TAINT DATA FLOW DIAGRAM LOGS ===
${latestAssessment.taintFlows.slice(0, budget.taint).map(t => `[STATIC_TAINT_FLOW] Variable [${t.sourceType}] channels directly into Critical Destination Sink [${t.sinkType}] along vector flow trajectory: ${t.flowPath}`).join('\n')}

=== REAL-TIME RUNTIME INSTRUMENTATION TELEMETRY CAPTURES (PLAIN-TEXT INJECTIONS FIRST) ===
${prioritizedRuntime.map(rf => `[RUNTIME_INTERCEPT_EVENT] Layer: ${rf.sourceType} | Interface Context: ${rf.sinkType} | String Real Value Captured: ${rf.actualValue}`).join('\n')}

=== WEB ELEMENT DOM HTML LAYOUT INTELLIGENCE ===
${latestAssessment.domArtifacts.slice(0, budget.dom).map(d => `[DOM_ELEMENT_ARTIFACT] Type: ${d.elementType} | Raw Node Layout Markings: ${d.elementHtml}`).join('\n')}

=== EXTRACTED BROWSER TRANS-MEMORY GLOBAL OBJECT STATES ===
${latestAssessment.browserStates.slice(0, budget.states).map(b => `[GLOBAL_WINDOW_STATE] Object Key Indicator: ${b.globalObject} | String Payload Content Blob: ${b.stateValue.substring(0, 600)}`).join('\n')}

=== WEBPACK CHUNKS DEPENDENCY GRAPH PATHS ===
${latestAssessment.executionGraphs.slice(0, budget.graphs).map(eg => `[WEBPACK_CHUNKS_DEPENDENCY] Target Module Identity: ${eg.identifier} | Action Reference Route: ${eg.dependencies}`).join('\n')}
`;

        const masterSystemInstruction = `You are an elite Application Security Researcher, Reverse Engineer, and Enterprise Code Auditor.
You have complete, direct, and unrestricted access to the application's structural graphs, prioritized variables, cryptographic blocks, and full asset telemetry provided below:
${analysisBlueprintPayload}

MANDATORY RESPONSE CONSTRAINTS:
1. NEVER state, imply, or suggest that you do not have direct access to the files, code, or application parameters. You possess the direct system logs and code extraction graphs. Act as if the target codebase is loaded natively in your current workspace environment.
2. All analytical report schemas, logic descriptions, and explanations MUST be output entirely in clear, professional English. Do not include any Hindi text or phrasing under any circumstances. Mark verified items using strict confirmation tags: [CONFIRMED], [LIKELY], or [POSSIBLE].`;

        activeSessionState.conversationHistory.push({ role: 'user', content: query });

        let apiKey = '';
        let endpointUrl = '';
        let requestPayload: any = {};

        if (selectedProviderNode === '1') {
          apiKey = (process.env.GEMINI_API_KEY || '').trim();
          endpointUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${apiKey}`;
          
          const standardHistoryParts = activeSessionState.conversationHistory.map(h => ({
            role: h.role === 'user' ? 'user' : 'model',
            parts: [{ text: h.content }]
          }));

          requestPayload = {
            system_instruction: { parts: [{ text: masterSystemInstruction }] },
            contents: standardHistoryParts
          };
        } else if (selectedProviderNode === '2' || selectedProviderNode === '3') {
          apiKey = selectedProviderNode === '2' ? (process.env.GROQ_API_KEY || '').trim() : (process.env.MISTRAL_API_KEY || '').trim();
          endpointUrl = selectedProviderNode === '2' ? 'https://api.groq.com/openai/v1/chat/completions' : 'https://api.mistral.ai/v1/chat/completions';
          
          const messages = [{ role: 'system', content: masterSystemInstruction }];
          activeSessionState.conversationHistory.forEach(h => {
            messages.push({ role: h.role, content: h.content });
          });

          requestPayload = {
            model: selectedProviderNode === '2' ? 'llama-3.3-70b-versatile' : 'mistral-large-latest',
            messages,
            temperature: 0.2
          };
        } else if (selectedProviderNode === '4') {
          apiKey = (process.env.COHERE_API_KEY || '').trim();
          endpointUrl = `https://api.cohere.ai/v1/chat`;
          
          const history = activeSessionState.conversationHistory.slice(0, -1).map(h => ({
            role: h.role === 'user' ? 'USER' : 'CHATBOT',
            message: h.content
          }));

          requestPayload = {
            model: 'command-r-plus',
            preamble: masterSystemInstruction,
            message: query,
            chat_history: history,
            temperature: 0.2
          };
        }

        const targetHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
        if (selectedProviderNode !== '1') targetHeaders['Authorization'] = `Bearer ${apiKey}`;

        // ✅ FIXED: Expanded time matrix boundaries from 30s to 60s for Mistral operations
        const controller = new AbortController();
        const networkTimeoutTrigger = setTimeout(() => controller.abort(), 60000);

        const startTime = Date.now();

        try {
          const response = await fetch(endpointUrl, { 
            method: 'POST', 
            headers: targetHeaders, 
            body: JSON.stringify(requestPayload),
            signal: controller.signal
          });
          
          clearTimeout(networkTimeoutTrigger);

          if (!response.ok) {
            const errorBody = await response.text();
            throw new Error(`Status ${response.status} -> ${errorBody}`);
          }

          const rawJSON: any = await response.json();
          let responseText = '';

          if (selectedProviderNode === '1') responseText = rawJSON.candidates?.[0]?.content?.parts?.[0]?.text || '';
          else if (selectedProviderNode === '2' || selectedProviderNode === '3') responseText = rawJSON.choices?.[0]?.message?.content || '';
          else if (selectedProviderNode === '4') responseText = rawJSON.text || '';

          activeSessionState.runtimeTelemetry.push({ provider: selectedProviderNode, latency: Date.now() - startTime, timestamp: Date.now() });
          activeSessionState.conversationHistory.push({ role: 'assistant', content: responseText });

          console.log(`\n${GREEN}----------------------------------------------------------------------${RESET}`);
          console.log(colorizeMarkdownResponse(responseText));
          console.log(`${GREEN}----------------------------------------------------------------------${RESET}`);

        } catch (err: any) {
          clearTimeout(networkTimeoutTrigger);
          if (err.name === 'AbortError') {
            const outNode = selectedProviderNode === '2' ? 'Groq' : selectedProviderNode === '3' ? 'Mistral' : 'Cohere';
            console.error(`\n${RED}❌ TIMEOUT CRITICAL: Upstream Node (${outNode}) failed to deliver a response packet within the strict 60-second optimization matrix.${RESET}\n`);
          } else {
            console.error(`\n${RED}❌ Upstream transaction request dropped: ${err.message}${RESET}\n`);
          }
        }

        askQuestion();
      });
    };

    askQuestion();
  };

  runConversationalLoopChannel();
}

launchAnalyzerConsole().catch(console.error);

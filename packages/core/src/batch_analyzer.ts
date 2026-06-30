import { PrismaClient } from '@prisma/client';
import * as readline from 'readline';
import * as path from 'path';
import * as fs from 'fs';
import { RiskClassificationEngine } from './services/riskClassificationEngine';
import { ReportingEngine } from './services/reportingEngine';

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

const SECRETFINDER_RULES: Record<string, RegExp> = {
  'Google Cloud API Key': /AIza[0-9A-Za-z-_]{35}/g,
  'AWS Access Key ID': /A[SK]IA[0-9A-Z]{16}/g,
  'AWS Secret Access Key Pattern': /(?:aws|secret|mock|key|access)(?:_|-| )*(?:key|secret)(?:_|-| )*['"]*[:= ]*['"]*([A-Za-z0-9/+=]{40})['"]/gi,
  'JSON Web Token (JWT)': /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  'Slack API Token Connection': /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
  'Stripe Live Secret Key': /sk_live_[0-9a-zA-Z]{24}/g,
  'GitHub Personal Access Token': /ghp_[0-9a-zA-Z]{36}/g,
  'Firebase Web API Configuration Key': /AIzaSy[A-Za-z0-9-_]{29}/g,
  'Facebook OAuth Access Token String': /EAACEdEose0cBA[0-9A-Za-z]+/g,
  'Twilio API Authentication SID Token': /AC[a-f0-9]{32}/g,
  'Mailgun API Cloud Access Private Key': /key-[0-9a-zA-Z]{32}/g,
  'Heroku Platform Infrastructure API Key': /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
  'Database Target Connection URI String': /(?:mongodb|postgresql|mysql|redis):\/\/([^@\s]+):([^@\s]+)@([^\s]+)/gi,
  'Asymmetric Cryptographic Private PEM Block': /-----BEGIN [A-Z]+ PRIVATE KEY-----/g,
  'Exposed Credentials Pattern': /(password\s*[`=:\"]+\s*[^\s\']+|pwd\s*[`=:\"]*\s*[^\s\']+)/gi,
  'Hardcoded Application Token/Secret Catch-All': /(?:strapi|token|auth|key|secret|config|credential)[a-zA-Z0-9_-]*\s*[`=:\"]+\s*['"]([a-zA-Z0-9-_~.+=]{24,})['"]/gi
};

function colorizeMarkdownResponse(text: string): string {
  return text
    .split('\n')
    .map(line => {
      if (line.startsWith('# ') || line.startsWith('=== ')) return `${BOLD}${MAGENTA}${line.toUpperCase()}${RESET}`;
      if (line.startsWith('## ')) return `\n${BOLD}${CYAN}${line}${RESET}`;
      if (line.startsWith('### ')) return `${BOLD}${BLUE}${line}${RESET}`;
      
      let updatedLine = line;
      if (updatedLine.includes('[CONFIRMED]')) updatedLine = updatedLine.replace('[CONFIRMED]', `${BG_RED}${BOLD}${WHITE}[CONFIRMED]${RESET}`);
      if (updatedLine.includes('[LIKELY]')) updatedLine = updatedLine.replace('[LIKELY]', `${BOLD}${YELLOW}[LIKELY]${RESET}`);
      if (updatedLine.includes('[POSSIBLE]')) updatedLine = updatedLine.replace('[POSSIBLE]', `${BOLD}${BLUE}[POSSIBLE]${RESET}`);
      return updatedLine;
    })
    .join('\n');
}

function compileOpenAPISpecificationFile(endpoints: any[]): string {
  const swaggerSkeleton: any = {
    openapi: '3.0.0',
    info: { title: 'Reverse Engineered Client API Map Blueprint Spec', version: '1.0.0', description: 'Auto-compiled schema.' },
    paths: {}
  };
  endpoints.forEach(e => {
    try {
      const urlObject = new URL(e.url);
      const pathname = urlObject.pathname || '/';
      const methodLower = e.method.toLowerCase();
      if (!swaggerSkeleton.paths[pathname]) swaggerSkeleton.paths[pathname] = {};
      swaggerSkeleton.paths[pathname][methodLower] = {
        summary: `Auto-Harvested Endpoint Resource`,
        responses: { '200': { description: 'Successful mapping capture.' } }
      };
    } catch (err) {}
  });
  return JSON.stringify(swaggerSkeleton, null, 2);
}

async function launchAnalyzerConsole() {
  const allAssessments = await prisma.assessment.findMany({
    orderBy: { createdAt: 'desc' },
    include: { endpoints: true, scripts: true, runtimeTaintFlows: true, domArtifacts: true, browserStates: true, executionGraphs: true }
  });

  if (!allAssessments || allAssessments.length === 0) {
    console.error(`\n${RED}${BOLD}❌ ABORT: No assessment database records found.${RESET}\n`);
    return;
  }

  const latestAssessment = allAssessments[0];
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  console.log(`\n${CYAN}======================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}🔥 SECVENTRA UNIFIED BULK AUDITING & AD-HOC INVESTIGATION CONSOLE CORE${RESET}`);
  console.log(`======================================================================${RESET}`);
  console.log(`${BOLD}Active Tracked Assessments :${RESET} ${GREEN}${allAssessments.length} Clusters Loaded${RESET}`);
  console.log(`${BOLD}Recent Scanning Focus      :${RESET} ${YELLOW}${latestAssessment.targetUrl}${RESET}`);
  console.log(`${CYAN}----------------------------------------------------------------------${RESET}`);
  console.log(`${BOLD}${WHITE}Select AI Provider Module Node or Offline Reporting Action:${RESET}`);
  console.log(` [1] ${BOLD}${CYAN}Google Gemini 2.5 Pro Core${RESET}`);
  console.log(` [2] ${BOLD}${GREEN}Groq Cloud Compute Grid${RESET} (Llama 3 70B Fast Chat⚡)`);
  console.log(` [3] ${BOLD}${MAGENTA}Mistral Large Infrastructure AI Core${RESET}`);
  console.log(` [4] ${BOLD}${BLUE}Cohere Command-R Plus Enterprise Cluster${RESET}`);
  console.log(` [5] ${BOLD}${YELLOW}Compile & Export Auto-Generated OpenAPI Swagger Specs JSON Schema 📄${RESET}`);
  console.log(` [6] ${BOLD}${WHITE}${BG_RED} DISPLAY MASTER TELEMETRY COMPONENT MAPS PER ACTIVE TARGET SCOPING BLOCK 🔍 ${RESET}`);
  console.log(`${CYAN}======================================================================${RESET}`);

  rl.question(`\n${BOLD}${WHITE}⚙ Choose Analytics Processing Vector Target (1-6): ${RESET}`, async (choice) => {
    const selectedOption = choice.trim();

    // AI Provider Registry
    const PROVIDER_NAMES: Record<string, string> = {
      '1': 'Google Gemini 2.5 Pro Core',
      '2': 'Groq Cloud Compute Grid (Llama 3 70B)',
      '3': 'Mistral Large Infrastructure AI Core',
      '4': 'Cohere Command-R Plus Enterprise Cluster'
    };

    // Display active connector layer after provider selection
    const activeEngine = PROVIDER_NAMES[selectedOption];
    if (activeEngine) {
      console.log(`\n======================================================================`);
      console.log(`[⚡] ACTIVE CONNECTOR LAYER: Initializing channel via ${activeEngine}`);
      console.log(`======================================================================\n`);
    }

    if (selectedOption === '5') {
      const collectiveEndpoints: any[] = [];
      allAssessments.forEach(a => collectiveEndpoints.push(...a.endpoints));
      const specPayloadString = compileOpenAPISpecificationFile(collectiveEndpoints);
      const outputPath = path.join(process.cwd(), 'openapi_spec.json');
      fs.writeFileSync(outputPath, specPayloadString, 'utf-8');
      console.log(`\n[${GREEN}✔${RESET}] OpenAPI validation spec written straight to: ${BOLD}${WHITE}${outputPath}${RESET}\n`);
      rl.close();
      return;
    }

    if (selectedOption === '6') {
      allAssessments.forEach(ass => {
        const uniqueSecretsTracker = new Set<string>();
        let secretSectionOutput = '';

        ass.scripts.forEach(script => {
          if (!script.rawContent) return;
          Object.entries(SECRETFINDER_RULES).forEach(([ruleName, pattern]) => {
            pattern.lastIndex = 0;
            let match;
            while ((match = pattern.exec(script.rawContent!)) !== null) {
              const value = match[0].trim();
              const uniqueKey = `${ruleName}-${value}`;
              if (!uniqueSecretsTracker.has(uniqueKey)) {
                uniqueSecretsTracker.add(uniqueKey);
                secretSectionOutput += `  ├── [${RED}${BOLD}SECRET_EXPOSURE${RESET}] Rule Match: ${YELLOW}${ruleName}${RESET}\n  │   └── Plaintext Token Value: ${BOLD}${WHITE}${value}${RESET}\n`;
              }
            }
          });
        });

        console.log(`\n🌐 ${BOLD}${WHITE}TARGET SCOPE HOSTNAME:${RESET} ${CYAN}${ass.targetUrl}${RESET}`);
        const frameworksMapped = ass.runtimeTaintFlows.filter(f => f.sourceType === 'FRAMEWORK_VERSION');
        frameworksMapped.forEach(fw => console.log(`  ├── [${GREEN}FRAMEWORK_PROFILE${RESET}] ${fw.sinkType} -> Active Version: ${BOLD}${WHITE}${fw.actualValue}${RESET}`));
        
        const xssViolationsAlerts = ass.runtimeTaintFlows.filter(f => f.sourceType === 'DOM_TAINT' && f.sinkType.includes('DYNAMIC_XSS_VIOLATION'));
        xssViolationsAlerts.forEach(xv => console.log(`  └── [${BG_RED}${BOLD}${WHITE}CRITICAL DYNAMIC XSS ALERT${RESET}] Sink reached. Data: ${RED}${xv.actualValue}${RESET}`));

        if (secretSectionOutput.length > 0) console.log(secretSectionOutput);
        else console.log(`  └── ${GREEN}✔ No plaintext secrets mapped via regex rules inside this asset.${RESET}`);
      });
      rl.close();
      return;
    }

    let combinedDeduplicatedSecretsBlueprint = '';
    allAssessments.forEach(ass => {
      const globalAICheckerSet = new Set<string>();
      ass.scripts.forEach(script => {
        if (!script.rawContent) return;
        Object.entries(SECRETFINDER_RULES).forEach(([ruleName, pattern]) => {
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(script.rawContent!)) !== null) {
            const val = match[0].trim();
            const uniqueKey = `${ass.targetUrl}-${ruleName}-${val}`;
            if (!globalAICheckerSet.has(uniqueKey)) {
              globalAICheckerSet.add(uniqueKey);
              combinedDeduplicatedSecretsBlueprint += `[Host: ${ass.targetUrl}] Rule: ${ruleName} | Key Data: ${val}\n`;
            }
          }
        });
      });
    });

    const dataGraphBlueprint = `
=== MASTER BATCH TARGET INFRASTRUCTURE CONTEXT ===
Recent Audited Domain Focused Origin: ${latestAssessment.targetUrl}
Total Historical Scopes In Database: ${allAssessments.length} Active Profiles

=== DEDUPLICATED SECRET DISCOVERIES (ALL SUBDOMAINS CLUSTERED) ===
${combinedDeduplicatedSecretsBlueprint.length > 0 ? combinedDeduplicatedSecretsBlueprint : 'No matches logged.'}

=== VERIFIED LIVE DYNAMIC DOM XSS VIOLATION LOG TRACES ===
${latestAssessment.runtimeTaintFlows.filter(rf => rf.sourceType === 'DOM_TAINT' && rf.sinkType.includes('DYNAMIC_XSS_VIOLATION')).map(rf => `Target Sink: ${rf.sinkType} | Evidence Value: ${rf.actualValue}`).join('\n')}
`;

    const masterSystemInstruction = `You are an elite Application Security Researcher and Expert Code Auditor. Analyze the attached blueprint data:\n${dataGraphBlueprint}\nAssist the user contextually based on findings. Output exclusively in English.`;

    let apiKey = '';
    let endpointUrl = '';
    let geminiContents: any[] = [];
    let openaiMessages: any[] = [];
    let cohereHistory: any[] = [];

    if (selectedOption === '1') {
      apiKey = process.env.GEMINI_API_KEY || '';
      endpointUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=${apiKey}`;
    } else if (selectedOption === '2' || selectedOption === '3') {
      apiKey = selectedOption === '2' ? (process.env.GROQ_API_KEY || '') : (process.env.MISTRAL_API_KEY || '');
      endpointUrl = selectedOption === '2' ? 'https://api.groq.com/openai/v1/chat/completions' : 'https://api.mistral.ai/v1/chat/completions';
      openaiMessages.push({ role: 'system', content: masterSystemInstruction });
    } else if (selectedOption === '4') {
      apiKey = process.env.COHERE_API_KEY || '';
      endpointUrl = `https://api.cohere.ai/v1/chat`;
    }

    const targetHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
    if (selectedOption !== '1') targetHeaders['Authorization'] = `Bearer ${apiKey}`;

    if (!apiKey) {
      console.error(`\n${RED}${BOLD}❌ API KEY MISSING: Provide corresponding environment variable before connection setup.${RESET}\n`);
      rl.close();
      return;
    }

    console.log(`\n${BOLD}${GREEN}⚡ CLUSTER MAP CONTEXT BOUNDED: AI Channel active. Type 'exit' to quit.`);

    const triggerInteractivePromptLoop = () => {
      rl.question(`\n${BOLD}${CYAN}🔬 Ask AI > ${RESET}`, async (userInput) => {
        const promptQuery = userInput.trim();
        if (promptQuery.toLowerCase() === 'exit') { rl.close(); return; }
        if (!promptQuery) { triggerInteractivePromptLoop(); return; }

        let activeLoopPayload: any = {};
        if (selectedOption === '1') {
          geminiContents.push({ role: 'user', parts: [{ text: promptQuery }] });
          activeLoopPayload = { system_instruction: { parts: [{ text: masterSystemInstruction }] }, contents: geminiContents };
        } else if (selectedOption === '2' || selectedOption === '3') {
          openaiMessages.push({ role: 'user', content: promptQuery });
          activeLoopPayload = { model: selectedOption === '2' ? 'llama3-70b-8192' : 'mistral-large-latest', messages: openaiMessages, temperature: 0.2 };
        } else if (selectedOption === '4') {
          activeLoopPayload = { model: 'command-r-plus', preamble: masterSystemInstruction, message: promptQuery, chat_history: cohereHistory, temperature: 0.2 };
        }

        // 🔥 FIXED: Explicit connection verification logging to output network diagnostic tracking metrics
        try {
          const chatRes = await fetch(endpointUrl, { method: 'POST', headers: targetHeaders, body: JSON.stringify(activeLoopPayload) });
          
          if (!chatRes.ok) {
            const errorPayloadText = await chatRes.text();
            throw new Error(`Upstream Node Connection Rejected (HTTP ${chatRes.status}): ${errorPayloadText}`);
          }

          const chatJSON: any = await chatRes.json();
          let chatVerdict = '';

          if (selectedOption === '1') chatVerdict = chatJSON.candidates?.[0]?.content?.parts?.[0]?.text || '';
          else if (selectedOption === '2' || selectedOption === '3') chatVerdict = chatJSON.choices?.[0]?.message?.content || '';
          else if (selectedOption === '4') chatVerdict = chatJSON.text || '';

          if (!chatVerdict) {
            console.error(`\n${RED}❌ Empty structure returned from host layout node. Checking fallback logging state.${RESET}`);
            console.log(JSON.stringify(chatJSON, null, 2));
          } else {
            console.log(`\n${GREEN}----------------------------------------------------------------------${RESET}`);
            console.log(colorizeMarkdownResponse(chatVerdict));
            console.log(`${GREEN}----------------------------------------------------------------------${RESET}`);

            if (selectedOption === '1') geminiContents.push({ role: 'model', parts: [{ text: chatVerdict }] });
            else if (selectedOption === '2' || selectedOption === '3') openaiMessages.push({ role: 'assistant', content: chatVerdict });
            else if (selectedOption === '4') {
              cohereHistory.push({ role: 'USER', message: promptQuery });
              cohereHistory.push({ role: 'CHATBOT', message: chatVerdict });
            }
          }
        } catch (chatErr: any) {
          console.error(`\n${RED}❌ Connection Core Exception: ${chatErr.message}${RESET}\n`);
        }
        triggerInteractivePromptLoop();
      });
    };
    triggerInteractivePromptLoop();
  });
}

launchAnalyzerConsole().catch(console.error);

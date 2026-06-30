import { chromium } from 'playwright';
import { PrismaClient } from '@prisma/client';
import * as readline from 'readline';
import * as process from 'process';
import * as fs from 'fs';
import * as path from 'path';
import { ASTEngine } from './services/astEngine';
import { TaintEngine } from './services/taintEngine';
import { WebpackEngine } from './services/webpackEngine';
import { InstrumentationEngine } from './services/instrumentationEngine';
import { DOMIntelligenceEngine } from './services/domIntelligenceEngine';
import { RiskClassificationEngine } from './services/riskClassificationEngine';

const prisma = new PrismaClient();

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const YELLOW = '\x1b[33m';
const WHITE = '\x1b[37m';

// Dynamic Network Verifier to filter dead targets instantly before browser allocation
async function isTargetAlive(targetUrl: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 7000); // 7-second aggressive timeout constraint

    const res = await fetch(targetUrl, { 
      method: 'GET', 
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Asset-Validation-Scanner/1.0' },
      signal: controller.signal 
    });
    clearTimeout(timeoutId);
    return true;
  } catch (e) {
    return false;
  }
}

// COHESIVE ANSI HELP MENU INTERFACE DESIGN
function displayHelpMenu(): void {
  console.log(`\n${CYAN}======================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}🌌 BREACH-VERSE - REVERSE ENGINEERING PLATFORM CONTROL SHELL${RESET}`);
  console.log(`======================================================================${RESET}`);
  console.log(`${BOLD}${WHITE}Usage Pattern:${RESET} npm start -- ["target_url" | "subdomains_list.txt"] ["options"]`);
  console.log(`\n${BOLD}${WHITE}CORE OPTIONS Constraints:${RESET}`);
  console.log(`  --headed       Opens browser virtualization in headed GUI mode.`);
  console.log(`  --help, -h     Brings up this granular operational pipeline menu.`);
  console.log(`\n${BOLD}${WHITE}AUTOMATION SCRIPTS PIPELINE WORKFLOWS:${RESET}`);
  console.log(`  ${YELLOW}npm start -- <input>${RESET}   Ingest singular endpoint target or bulk subdomain files.`);
  console.log("  " + YELLOW + "npm run batch" + RESET + "          Launches dynamic multi-provider AI context console (Option 1-6).");
  console.log(`  ${YELLOW}npm run clear${RESET}          Wipes all temporary reports, maps, and empties SQLite states.`);
  console.log(`${CYAN}======================================================================${RESET}\n`);
}

async function scanSingleTarget(targetUrl: string, isHeaded: boolean) {
  const parserUrlObject = new URL(targetUrl);
  parserUrlObject.searchParams.set('secventra_fuzz', 'secventra_trace');
  parserUrlObject.hash = 'secventra_hash';
  const fuzzedTargetNavigationUrl = parserUrlObject.toString();

  console.log(`\n${CYAN}[*] Processing Target Scope Layer: ${RESET}${BOLD}${YELLOW}${targetUrl}${RESET}`);
  
  const alive = await isTargetAlive(targetUrl);
  if (!alive) {
    console.error(` [${RED}❌ SKIP${RESET}] Target subdomain host appears offline or unreachable.`);
    return;
  }
  console.log(` [${GREEN}✔ LIVE${RESET}] Injecting dynamic vulnerability parameter tracking hooks...`);

  const browser = await chromium.launch({ 
    headless: !isHeaded,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({ viewport: isHeaded ? null : { width: 1280, height: 720 } });
  const page = await context.newPage();

  await InstrumentationEngine.injectSecurityHooks(page);

  const currentAssessment = await prisma.assessment.create({ data: { targetUrl } });
  console.log(` [${GREEN}✔${RESET}] DB Record Instantiated. ID: ${GREEN}${currentAssessment.id}${RESET}`);

  page.on('response', async (response) => {
    const url = response.url();
    const method = response.request().method();
    const contentType = response.headers()['content-type'] || 'unknown/asset';

    if (url.match(/\.(png|jpg|jpeg|gif|svg|woff2|css|ico)$/i)) return;
    if (RiskClassificationEngine.isFalsePositiveAsset(url)) return; 

    try {
      const parsedFileName = url.split('/').pop()?.split('?')[0] || 'index_root';
      await prisma.endpoint.create({
        data: {
          assessmentId: currentAssessment.id,
          method,
          url,
          sourceFile: parsedFileName,
          type: contentType.split(';')[0]
        }
      });

      if (contentType.includes('javascript') || contentType.includes('html') || contentType.includes('json')) {
        const rawContent = await response.text();
        if (!rawContent || rawContent.trim().length === 0) return;

        const savedScript = await prisma.script.create({
          data: {
            url,
            type: contentType.includes('json') ? 'JSON_DATA' : contentType.includes('html') ? 'HTML_DOM' : 'JS_CHUNK',
            rawContent,
            assessmentId: currentAssessment.id
          }
        });

        const astMetrics = ASTEngine.parseCodebase(rawContent, parsedFileName);
        for (const func of astMetrics.functions) {
          await prisma.functionInventory.create({
            data: {
              name: func.name,
              sourceFile: func.file,
              startLine: func.startLine,
              endLine: func.endLine,
              isAsync: func.isAsync,
              params: func.params.join(','),
              assessmentId: currentAssessment.id
            }
          });
        }

        const traces = TaintEngine.traceTaint(rawContent);
        for (const tr of traces) {
          await prisma.taintFlow.create({
            data: {
              sourceType: tr.source,
              sinkType: tr.sink,
              flowPath: tr.path.join(' -> '),
              confidence: tr.confidence,
              assessmentId: currentAssessment.id
            }
          });
        }

        const cryptoSignatures = TaintEngine.auditCryptoCiphers(rawContent, parsedFileName);
        for (const cs of cryptoSignatures) {
          await prisma.cryptoOperation.create({
            data: {
              type: cs.type,
              mode: cs.mode,
              keySource: cs.keySource,
              ivSource: cs.ivSource,
              outputFormat: cs.outputFormat,
              destination: cs.destination,
              sourceFile: cs.file,
              assessmentId: currentAssessment.id
            }
          });
        }

        const webpackFlows = WebpackEngine.traceWebpackModules(rawContent);
        for (const flow of webpackFlows) {
          await prisma.executionGraph.create({
            data: {
              moduleType: 'WEBPACK_MODULE',
              identifier: parsedFileName,
              dependencies: flow,
              assessmentId: currentAssessment.id
            }
          });
        }

        await WebpackEngine.discoverAndProcessMaps(savedScript);
      }
    } catch (e) {}
  });

  try {
    await page.goto(fuzzedTargetNavigationUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    await page.waitForTimeout(8000); 

    const frameworks = await InstrumentationEngine.harvestDetectedFrameworks(page);
    for (const fw of frameworks) {
      await prisma.runtimeTaintFlow.create({
        data: {
          sourceType: 'FRAMEWORK_VERSION',
          sinkType: fw.framework,
          actualValue: fw.version,
          executionStep: `Detected active software engineering blueprint: ${fw.framework}`,
          assessmentId: currentAssessment.id
        }
      });
    }

    const domArtifacts = await DOMIntelligenceEngine.analyzeRenderedDOM(page);
    for (const art of domArtifacts) {
      await prisma.domArtifact.create({
        data: {
          elementType: art.elementType,
          elementHtml: art.elementHtml,
          attributes: JSON.stringify(art.attributes),
          assessmentId: currentAssessment.id
        }
      });
    }

    const globalStates = await InstrumentationEngine.harvestBrowserGlobalStates(page);
    for (const gs of globalStates) {
      await prisma.browserState.create({
        data: {
          globalObject: gs.globalObject,
          extractedKey: 'ROOT_GLOBAL_STATE_OBJECT',
          stateValue: gs.parsedJSON,
          assessmentId: currentAssessment.id
        }
      });
    }

    const telemetryEvents = await InstrumentationEngine.extractRuntimeTraces(page);
    for (const ev of telemetryEvents) {
      await prisma.runtimeTaintFlow.create({
        data: {
          sourceType: ev.layer,
          sinkType: ev.meta,
          actualValue: ev.payload,
          executionStep: `Runtime telemetry validation capture: ${ev.timestamp}`,
          assessmentId: currentAssessment.id
        }
      });
    }

  } catch (err: any) {
    console.error(` [${RED}❌${RESET}] Navigation Exception: ${err.message}`);
  } finally { // 🔥 FIXED: Changed from 'final' to 'finally' to fix compile error
    await browser.close();
    console.log(` [${GREEN}✔${RESET}] Target transaction closed out safely.`);
  }
}

async function startCoreCapture() {
  const args = process.argv.slice(2);
  
  // INTERCEPT HELP FLAG COMMANDS INSTANTLY BEFORE BOOTSTRAP
  if (args.includes('--help') || args.includes('-h')) {
    displayHelpMenu();
    return;
  }

  const isHeaded = args.includes('--headed');
  const inputParam = args.filter(arg => !arg.startsWith('--'))[0] || 'https://example.com';
  
  console.log(`\n${CYAN}======================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}🚀 ENTERPRISE REVERSE ENGINEERING BULK AUTOMATION LAYER${RESET}`);
  console.log(`======================================================================${RESET}`);

  let rawTargets: string[] = [];

  if (fs.existsSync(inputParam)) {
    console.log(`[+] Subdomain list text file asset detected: ${BOLD}${WHITE}${path.resolve(inputParam)}${RESET}`);
    const fileLines = fs.readFileSync(inputParam, 'utf-8').split('\n');
    for (let line of fileLines) {
      line = line.trim();
      if (line && !line.startsWith('#')) {
        rawTargets.push(line.startsWith('http') ? line : `https://${line}`);
      }
    }
  } else {
    rawTargets.push(inputParam.startsWith('http') ? inputParam : `https://${inputParam}`);
  }

  const targetsQueue = Array.from(new Set(rawTargets));
  console.log(`[+] Mapped ${GREEN}${targetsQueue.length}${RESET} unique scopes into target queue (Duplicates Excluded).`);

  for (let i = 0; i < targetsQueue.length; i++) {
    console.log(`\n[ Running Queue Step: ${i + 1} / ${targetsQueue.length} ]`);
    await scanSingleTarget(targetsQueue[i], isHeaded);
  }

  console.log(`\n${GREEN}======================================================================${RESET}`);
  console.log(`${BOLD}${GREEN}✔ ALL SUBDOMAINS SCANNED: Telemetry mapping matrices written cleanly to DB.`);
  console.log(`👉 Fire 'npm run batch' now to audit collected artifacts with the AI core.${RESET}`);
  console.log(`${GREEN}======================================================================${RESET}\n`);
}

startCoreCapture().catch(console.error);

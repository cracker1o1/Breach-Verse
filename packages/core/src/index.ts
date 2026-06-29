import { chromium } from 'playwright';
import { PrismaClient } from '@prisma/client';
import * as readline from 'readline';
import * as process from 'process';
import 'dotenv/config'; // ✅ Added to automatically initialize process.env across core pipeline runtimes

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

async function startCoreCapture() {
  const args = process.argv.slice(2);
  const isHeaded = args.includes('--headed');
  const urlArg = args.filter(arg => !arg.startsWith('--'))[0];
  const targetUrl = urlArg || 'https://example.com';
  
  console.log(`\n${CYAN}======================================================================${RESET}`);
  console.log(`${BOLD}${CYAN}🚀 ENTERPRISE REVERSE ENGINEERING & INTELLIGENCE SCANNERS CORE${RESET}`);
  console.log(`${CYAN}======================================================================${RESET}`);

  const browser = await chromium.launch({ 
    headless: !isHeaded,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({ viewport: isHeaded ? null : { width: 1280, height: 720 } });
  const page = await context.newPage();

  await InstrumentationEngine.injectSecurityHooks(page);

  const currentAssessment = await prisma.assessment.create({ data: { targetUrl } });
  console.log(`[${GREEN}✔${RESET}] Assessment Session initialized inside database. ID: ${GREEN}${currentAssessment.id}${RESET}`);

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
    } catch (e) {
      // Catch layout boundaries safely
    }
  });

  try {
    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
    
    if (isHeaded) {
      console.log(`\n[${BOLD}${GREEN}🎯 LIVE INTERACTIVE CONSOLE POPULATED${RESET}]`);
      console.log(`👉 Interact manually inside the browser viewport. Pre-render proxies are writing logs...`);
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      await new Promise<void>((resolve) => {
        rl.question(`\n⌨️  Press [${BOLD}${RED}ENTER${RESET}] in this shell when you are ready to terminate and process graphs... `, () => {
          rl.close();
          resolve();
        });
      });
    } else {
      console.log(`[*] Holding session state active to collect async background tasks...`);
      await page.waitForTimeout(15000);
    }

    console.log(`[*] Parsing active DOM layouts for element artifacts...`);
    const domArtifacts = await DOMIntelligenceEngine.analyzeRenderedDOM(page);
    for (const art of domArtifacts) {
      await prisma.dOMArtifact.create({
        data: {
          elementType: art.elementType,
          elementHtml: art.elementHtml,
          attributes: JSON.stringify(art.attributes),
          assessmentId: currentAssessment.id
        }
      });
    }

    console.log(`[*] Harvesting transient browser global state objects...`);
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
    console.log(`[${GREEN}✔${RESET}] Capture complete. Extracted ${telemetryEvents.length} runtime execution events via memory proxies.`);
    
    for (const ev of telemetryEvents) {
      await prisma.runtimeTaintFlow.create({
        data: {
          sourceType: ev.layer,
          sinkType: ev.meta,
          actualValue: ev.payload,
          executionStep: `Observed at system runtime timestamp: ${ev.timestamp}`,
          assessmentId: currentAssessment.id
        }
      });

      if (ev.payload.includes('Authorization') || ev.payload.includes('eyJ')) {
        await prisma.jWTGraph.create({
          data: {
            tokenSnippet: ev.payload.substring(0, 100),
            lifecycleStep: ev.layer === 'FETCH_INTERCEPT' ? 'TRANSMISSION' : 'STORAGE',
            location: ev.layer === 'FETCH_INTERCEPT' ? 'AuthHeader' : 'localStorage',
            destination: ev.meta,
            assessmentId: currentAssessment.id
          }
        });
      }
    }

  } catch (err: any) {
    console.error(`[!] Navigation failure block: ${err.message}`);
  } finally {
    console.log(`[${GREEN}✔${RESET}] Target asset assessment baseline successfully committed to storage.`);
    console.log(`${CYAN}======================================================================${RESET}\n`);
    await browser.close();
  }
}

startCoreCapture().catch(console.error);

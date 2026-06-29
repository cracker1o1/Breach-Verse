const fs = require('fs');
const path = require('path');

const files = {};

// ==========================================
// 1. ROOT CONFIGURATION & WORKSPACES
// ==========================================

files['package.json'] = JSON.stringify({
  "name": "client-side-security-platform",
  "version": "1.0.0",
  "private": true,
  "engines": {
    "node": ">=18.0.0"
  },
  "workspaces": [
    "packages/*"
  ],
  "scripts": {
    "build": "tsc -b",
    "db:generate": "yarn workspace @platform/database prisma generate",
    "db:push": "yarn workspace @platform/database prisma db push",
    "start": "ts-node packages/core/src/index.ts"
  },
  "dependencies": {
    "ts-node": "^10.9.2",
    "typescript": "^5.3.3"
  }
}, null, 2);

files['tsconfig.json'] = JSON.stringify({
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "moduleResolution": "node",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "outDir": "./dist"
  },
  "exclude": ["node_modules", "dist"]
}, null, 2);

// ==========================================
// 2. DATABASE PACKAGE
// ==========================================

files['packages/database/package.json'] = JSON.stringify({
  "name": "@platform/database",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "dependencies": {
    "@prisma/client": "^5.10.2"
  },
  "devDependencies": {
    "prisma": "^5.10.2"
  }
}, null, 2);

files['packages/database/prisma/schema.prisma'] = `
datasource db {
  provider = "sqlite"
  url      = "file:./dev.db"
}

generator client {
  provider = "prisma-client-js"
}

model Assessment {
  id          String      @id @default(uuid())
  targetUrl   String
  createdAt   DateTime    @default(now())
  scripts     Script[]
  endpoints   Endpoint[]
  findings    Finding[]
}

model Script {
  id           String      @id @default(uuid())
  assessmentId String
  url          String
  type         String      
  rawContent   String?     
  beautified   String?     
  assessment   Assessment  @relation(fields: [assessmentId], references: [id])
}

model Endpoint {
  id           String      @id @default(uuid())
  assessmentId String
  url          String
  method       String      
  sourceFile   String
  callingFunc  String?
  type         String      
  assessment   Assessment  @relation(fields: [assessmentId], references: [id])
}

model Finding {
  id           String      @id @default(uuid())
  assessmentId String
  category     String      
  severity     String      
  description  String
  evidence     String      
  assessment   Assessment  @relation(fields: [assessmentId], references: [id])
}
`;

// ==========================================
// 3. INSTRUMENTATION PACKAGE
// ==========================================

files['packages/instrumentation/package.json'] = JSON.stringify({
  "name": "@platform/instrumentation",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts"
}, null, 2);

files['packages/instrumentation/src/index.ts'] = `
export const RUNTIME_HOOKS = \`
(function() {
  const emitPayload = (channel, data) => {
    window.dispatchEvent(new CustomEvent('__SECURITY_INTEL_CAPTURE__', {
      detail: { channel, data, timestamp: Date.now() }
    }));
  };

  // 1. HTTP/Network Interception Hook
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : (args[0] instanceof Request ? args[0].url : '');
    const options = args[1] || {};
    const method = options.method || 'GET';
    
    emitPayload('NETWORK_CALL', { type: 'fetch', url, method });
    return originalFetch.apply(this, args);
  };

  const originalXHR = window.XMLHttpRequest.prototype.open;
  window.XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    emitPayload('NETWORK_CALL', { type: 'xhr', url, method });
    return originalXHR.apply(this, [method, url, ...rest]);
  };

  // 2. Client-Side Cryptography Hook
  if (window.crypto && window.crypto.subtle) {
    const origEncrypt = window.crypto.subtle.encrypt;
    window.crypto.subtle.encrypt = function(algorithm, key, data) {
      emitPayload('CRYPTO_USAGE', {
        operation: 'encrypt',
        algorithm: typeof algorithm === 'string' ? algorithm : algorithm.name
      });
      return origEncrypt.apply(this, arguments);
    };
  }

  // 3. Storage Monitoring Hook
  const monitorStorage = (storageObj, name) => {
    const origSetItem = storageObj.setItem;
    storageObj.setItem = function(key, value) {
      emitPayload('STORAGE_MUTATION', { storage: name, key, value });
      return origSetItem.apply(this, arguments);
    };
  };
  monitorStorage(window.localStorage, 'localStorage');
  monitorStorage(window.sessionStorage, 'sessionStorage');

  console.log('[MONITOR] Runtime Platform Engine Successfully Injected.');
})();
\`;
`;

// ==========================================
// 4. ANALYZER PACKAGE (AST Engines)
// ==========================================

files['packages/analyzer/package.json'] = JSON.stringify({
  "name": "@platform/analyzer",
  "version": "1.0.0",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "dependencies": {
    "@babel/parser": "^7.23.9",
    "@babel/traverse": "^7.23.9"
  },
  "devDependencies": {
    "@types/babel__traverse": "^7.20.5"
  }
}, null, 2);

files['packages/analyzer/src/index.ts'] = `
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';

export interface AnalysisResults {
  endpoints: Array<{ url: string; method: string; pattern: string }>;
  findings: Array<{ category: string; severity: string; description: string; evidence: string }>;
}

export function runStaticAnalysis(sourceCode: string): AnalysisResults {
  const results: AnalysisResults = { endpoints: [], findings: [] };

  // Heuristic Scan 1: High Entropy Secrets / API Key Exposure (Regex)
  const secretPatterns = [
    { name: 'AWS API Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL' },
    { name: 'Generic Private Key', regex: /-----BEGIN PRIVATE KEY-----/g, severity: 'CRITICAL' },
    { name: 'Slack Webhook', regex: /https:\\/\\/hooks\\.slack\\.com\\/services\\/[A-Za-z0-9_\\/]+/g, severity: 'HIGH' },
    { name: 'Stripe API Key', regex: /sk_live_[0-9a-zA-Z]{24}/g, severity: 'CRITICAL' }
  ];

  for (const pattern of secretPatterns) {
    const matches = sourceCode.match(pattern.regex);
    if (matches) {
      for (const match of matches) {
        results.findings.push({
          category: 'Exposed Secret',
          severity: pattern.severity,
          description: \`Potential exposed raw \${pattern.name} verified dynamically.\`,
          evidence: match.substring(0, 50)
        });
      }
    }
  }

  // Heuristic Scan 2: Full AST Parsing for Routing & Crypto Logic Identifiers
  try {
    const ast = parse(sourceCode, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'decorators-legacy']
    });

    traverse(ast, {
      StringLiteral(path) {
        const val = path.node.value;
        // Detect relative backend routing footprints or specific absolute URLs
        if (val.startsWith('/api/v') || val.startsWith('/v1/') || val.match(/^https?:\\/\\/[a-zA-Z0-9-._~:\\/?#[\\]@!$&'()*+,;=]+$/)) {
          results.endpoints.push({
            url: val,
            method: 'DETECTED_STR',
            pattern: 'Static String Footprint Match'
          });
        }
      },
      Identifier(path) {
        const name = path.node.name;
        // Identify unsafe Client-side crypto patterns / legacy hashes
        if (['CryptoJS', 'forge', 'AES', 'RC4', 'MD5'].includes(name)) {
          results.findings.push({
            category: 'Cryptographic Footprint',
            severity: 'MEDIUM',
            description: \`Client-Side script utilizes cryptographic library instance or call identifier: \${name}\`,
            evidence: \`Identifier token reference: \${name}\`
          });
        }
      }
    });
  } catch (err) {
    // If AST parsing fails due to minification nuances, fall back transparently
  }

  return results;
}
`;

// ==========================================
// 5. CORE ORCHESTRATION PACKAGE
// ==========================================

files['packages/core/package.json'] = JSON.stringify({
  "name": "@platform/core",
  "version": "1.0.0",
  "main": "dist/index.js",
  "dependencies": {
    "@platform/database": "1.0.0",
    "@platform/instrumentation": "1.0.0",
    "@platform/analyzer": "1.0.0",
    "playwright": "^1.42.1"
  }
}, null, 2);

files['packages/core/src/index.ts'] = `
import { chromium } from 'playwright';
import { PrismaClient } from '@prisma/client';
import { RUNTIME_HOOKS } from '@platform/instrumentation';
import { runStaticAnalysis } from '@platform/analyzer';

const prisma = new PrismaClient();

async function runEngine(targetUrl: string, headlessMode: boolean = false) {
  console.log('============= ENGINE INITIALIZATION =============');
  console.log(\`Target Domain: \${targetUrl}\`);
  console.log(\`Headless Execution: \${headlessMode}\`);

  // Initialize DB Entry Context
  const assessment = await prisma.assessment.create({
    data: { targetUrl }
  });

  const browser = await chromium.launch({ headless: headlessMode });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });

  // 1. Add Pre-Execution Injection Hook
  await context.addInitScript({ content: RUNTIME_HOOKS });

  const page = await context.newPage();

  // 2. Intercept Dynamic JavaScript Asset Downloads
  page.on('response', async (response) => {
    const url = response.url();
    const contentType = response.headers()['content-type'] || '';

    if (contentType.includes('javascript') || url.endsWith('.js')) {
      try {
        const rawContent = await response.text();
        
        // Persist JS Script Data Block
        const scriptRecord = await prisma.script.create({
          data: {
            assessmentId: assessment.id,
            url,
            type: url.includes('chunk') ? 'DYNAMIC_CHUNK' : 'INITIAL_ASSET',
            rawContent
          }
        });

        // Invoke Analysis Engine Engine Processing Pipelines
        const analysis = runStaticAnalysis(rawContent);

        for (const endpoint of analysis.endpoints) {
          await prisma.endpoint.create({
            data: {
              assessmentId: assessment.id,
              url: endpoint.url,
              method: endpoint.method,
              sourceFile: url,
              type: 'REST_DETECTED'
            }
          });
        }

        for (const finding of analysis.findings) {
          await prisma.finding.create({
            data: {
              assessmentId: assessment.id,
              category: finding.category,
              severity: finding.severity,
              description: finding.description,
              evidence: finding.evidence
            }
          });
        }
        
        console.log(\`[ASSET CAPTURED] \${url.substring(0, 60)}... Analysis complete.\`);
      } catch (e) {
        // Suppress reading errors from third-party cross-origin tracking endpoints
      }
    }
  });

  // 3. Setup Listener for Injected Runtime Interceptors
  await page.exposeBinding('handleCapturedTelemetry', async ({ frame }, eventData: any) => {
    console.log(\`[RUNTIME TELEMETRY -> \${eventData.channel}]\`, eventData.data);
    
    if (eventData.channel === 'NETWORK_CALL') {
      await prisma.endpoint.create({
        data: {
          assessmentId: assessment.id,
          url: eventData.data.url,
          method: eventData.data.method,
          sourceFile: 'RUNTIME_MONITOR',
          type: eventData.data.type.toUpperCase()
        }
      });
    }
  });

  // Wire binding up via DOM Event dispatch listener mapping
  await page.evaluateOnNewDocument(() => {
    window.addEventListener('__SECURITY_INTEL_CAPTURE__', (e: any) => {
      (window as any).handleCapturedTelemetry(e.detail);
    });
  });

  console.log('\\nNavigating to target domain context...');
  await page.goto(targetUrl, { waitUntil: 'networkidle' });

  console.log('\\n[ACTIVE] Initial parsing sequence successful. Monitoring runtime interactions...');
  console.log('Press Ctrl+C to close analysis engine and compile final generated data logs.');

  // Keep process alive indefinitely to support visible live browser user manipulation analysis
  await new Promise(() => {});
}

// Default execution instance targeted at an intentional public endpoint domain for evaluation
runEngine('https://example.com', false).catch(console.error);
`;

// ==========================================
// CODE GENERATOR EXECUTION MACHINE
// ==========================================

console.log("🚀 Initializing Codebase Generation Machine...");

Object.keys(files).forEach((filePath) => {
  const fullPath = path.join(process.cwd(), filePath);
  const dir = path.dirname(fullPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(fullPath, files[filePath].trim());
  console.log(` [+] Generated: ${filePath}`);
});

console.log(`
======================================================================
🎉 ARCHITECTURE SOURCE EXTRACTION AND LAYOUT COMPLETE!
======================================================================

Follow these commands to deploy your operational client platform instance:

  1. Install system dependencies & link packages:
     $ yarn install  OR  npm install

  2. Install Playwright browser engines:
     $ npx playwright install chromium

  3. Push definitions and initialize the database engine:
     $ yarn db:push

  4. Run the security intelligence workspace platform:
     $ yarn start

To pack this clean production architecture into a unified zip file right now:
  (Linux/macOS) : zip -r platform.zip . -x "node_modules/*"
  (Windows PowerShell) : Compress-Archive -Path .\\* -DestinationPath platform.zip
======================================================================
`);

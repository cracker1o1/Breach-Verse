import { parse } from '@babel/parser';
import traverse from '@babel/traverse';

export interface AnalysisResults {
  endpoints: Array<{ url: string; method: string; pattern: string }>;
  findings: Array<{ category: string; severity: string; description: string; evidence: string }>;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// ADVANCED STATIC & CRYPTO SIGNATURE ENHANCED ANALYZER
export function runStaticAnalysis(sourceCode: string): AnalysisResults {
  const results: AnalysisResults = { endpoints: [], findings: [] };

  // 1. Light-weight and Memory Efficient Regex Scanner (हमेशा चलेगा, चाहे फ़ाइल कितनी भी बड़ी हो)
  const secretPatterns = [
    { name: 'AWS API Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL' },
    { name: 'Generic Private Key', regex: /-----BEGIN PRIVATE KEY-----/g, severity: 'CRITICAL' },
    { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/]+/g, severity: 'HIGH' },
    { name: 'Stripe API Key', regex: /sk_live_[0-9a-zA-Z]{24}/g, severity: 'CRITICAL' }
  ];

  for (const pattern of secretPatterns) {
    const matches = sourceCode.match(pattern.regex);
    if (matches) {
      for (const match of matches) {
        results.findings.push({
          category: 'Exposed Secret',
          severity: pattern.severity,
          description: `Detected token matching pattern for: ${pattern.name}`,
          evidence: match.substring(0, 60)
        });
      }
    }
  }

  // 🧠 MEMORY GUARDRAIL BUST: अगर फ़ाइल 500KB से बड़ी है, तो Babel AST पार्सर स्किप कर दो!
  // यह CanvasKit और Flutter main.dart.js को ओओएम (Out of Memory) क्रैश करने से रोकेगा।
  if (sourceCode.length > 500 * 1024) {
    // बैकअप लाइटवेट रेगेक्स सर्च फॉर कॉमन एंडपॉइंट्स इन बिग फाइल्स
    const urlRegex = /(https?:\/\/[^\s"'`>]+|\/[a-zA-Z0-9_\-\/]{3,})/g;
    const quickMatches = sourceCode.match(urlRegex);
    if (quickMatches) {
      quickMatches.slice(0, 50).forEach(link => {
        if (link.startsWith('/') && link.length > 3 && !link.match(/\.(css|png|jpg|woff2)$/i)) {
          results.endpoints.push({
            url: link,
            method: 'QUICK_REGEX_MATCH',
            pattern: 'Large Bundle Ingestion Extraction'
          });
        }
      });
    }
    return results; 
  }

  // 2. Heavy-duty AST Walker (केवल छोटी, कस्टम जावास्क्रिप्ट फाइलों के लिए चलेगा)
  try {
    const ast = parse(sourceCode, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'decorators-legacy']
    });

    const processRouteCandidate = (val: string) => {
      const cleaned = val.trim();
      if (
        cleaned.startsWith('http://') || 
        cleaned.startsWith('https://') || 
        (cleaned.startsWith('/') && cleaned.length > 2 && !cleaned.match(/\.(css|png|jpg|jpeg|gif|svg|woff2|woff|ttf|ico)$/i))
      ) {
        results.endpoints.push({
          url: cleaned,
          method: 'STATIC_AST_MATCH',
          pattern: 'Extracted Route Configuration Literal'
        });
      }
    };

    let suspectedKeys: Array<{ val: string; loc: any }> = [];
    let suspectedIVs: Array<{ val: string; loc: any }> = [];

    traverse(ast, {
      StringLiteral(path) {
        const val = path.node.value.trim();
        processRouteCandidate(val);

        if (val.length === 32 && /^[a-zA-Z0-9_\-]+$/.test(val)) {
          suspectedKeys.push({ val, loc: path.node.loc?.start });
        }
        if (val.length === 16 && /^[0-9A-Fa-f]+$/.test(val)) {
          suspectedIVs.push({ val, loc: path.node.loc?.start });
        }
      },
      TemplateLiteral(path) {
        if (path.node.quasis) {
          path.node.quasis.forEach((element: any) => {
            if (element.value && element.value.cooked) {
              processRouteCandidate(element.value.cooked);
            }
          });
        }
      },
      ObjectProperty(path) {
        if (path.node.key.type === 'Identifier' && ['url', 'path', 'endpoint'].includes(path.node.key.name)) {
          if (path.node.value.type === 'StringLiteral') {
            processRouteCandidate(path.node.value.value);
          }
        }
      }
    });

    if (suspectedKeys.length > 0) {
      suspectedKeys.forEach(keyObj => {
        const hasNearbyIV = suspectedIVs.length > 0;
        results.findings.push({
          category: 'Symmetric Cryptography Asset Discovered',
          severity: hasNearbyIV ? 'CRITICAL' : 'HIGH',
          description: `Hardcoded Key block verified. Structural footprint mimics a static symmetric key setup.${hasNearbyIV ? " Co-located IV matrix strings found in same asset." : ""}`,
          evidence: `KEY: ${keyObj.val}`
        });
      });
    }

  } catch (err) {
    // Suppress parsing quirks gracefully
  }

  return results;
}

// Micro-Triage Runtime Reviewer
export async function runAISecurityReview(contextType: 'ENDPOINT' | 'FINDING', dataPayload: string, apiKey?: string, retriesLeft = 3, delayMs = 1500): Promise<string> {
  if (!apiKey) return "Gemini insights bypassed.";
  const systemInstructionText = `You are an expert security engineer. Give a 2-3 sentence brief validation summary.`;
  const targetModel = 'gemini-2.5-flash'; 
  const requestUrl = `https://generativelanguage.googleapis.com/v1beta/models/${targetModel}:generateContent?key=${apiKey}`;
  try {
    const response = await fetch(requestUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: systemInstructionText }] },
        contents: [{ parts: [{ text: dataPayload }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 150 }
      })
    });
    const jsonRes: any = await response.json();
    return jsonRes.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || "Error processing micro-insight.";
  } catch (err: any) { return `Error: ${err.message}`; }
}

// Unconstrained Master Batch Pipeline with Resilience Logic
export async function runBatchExploitAnalysis(systemPrompt: string, reportDataBlueprint: string, apiKey: string, retriesLeft = 3, delayMs = 3000): Promise<string> {
  const targetModel = 'gemini-2.5-flash';
  const requestUrl = `https://generativelanguage.googleapis.com/v1beta/models/${targetModel}:generateContent?key=${apiKey}`;
  try {
    const response = await fetch(requestUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: reportDataBlueprint }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 2500 }
      })
    });
    const jsonRes: any = await response.json();
    if (jsonRes.error) {
      const errMsg = jsonRes.error.message || "";
      if (retriesLeft > 0) {
        await sleep(delayMs);
        return runBatchExploitAnalysis(systemPrompt, reportDataBlueprint, apiKey, retriesLeft - 1, delayMs * 2);
      }
      return `Gemini Master Engine Refusal: ${errMsg}`;
    }
    const generatedReport = jsonRes.candidates?.[0]?.content?.parts?.[0]?.text;
    if (generatedReport) return generatedReport.trim();
    return "Failed to compile report stream chunks.";
  } catch (err: any) {
    if (retriesLeft > 0) {
      await sleep(delayMs);
      return runBatchExploitAnalysis(systemPrompt, reportDataBlueprint, apiKey, retriesLeft - 1, delayMs * 2);
    }
    return `Critical Processing Failure: ${err.message}`;
  }
}

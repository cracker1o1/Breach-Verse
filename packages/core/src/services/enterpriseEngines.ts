import { Finding, IEnterpriseEngine, FindingType, SeverityLevel, Verdict, Evidence } from '../types/platform';
import * as crypto from 'crypto';

export class ShannonEntropyEngine implements IEnterpriseEngine {
  public name = 'Shannon Entropy Engine';
  public enabled = true;

  public static calculateEntropy(str: string): number {
    const frequencies: Record<string, number> = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  public async process(findings: Finding[]): Promise<Finding[]> {
    for (const finding of findings) {
      finding.entropy = ShannonEntropyEngine.calculateEntropy(finding.raw);
    }
    return findings;
  }
}

export class DecoderEngine implements IEnterpriseEngine {
  public name = 'Decoder Engine';
  public enabled = true;

  private attemptDecode(input: string): { type: string; output: string } | null {
    if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0 && input.length >= 8) {
      try {
        const decoded = Buffer.from(input, 'hex').toString('utf-8');
        if (/[\x20-\x7E]/.test(decoded)) return { type: 'Hexadecimal Sequence', output: decoded };
      } catch (e) {}
    }
    if (/^[A-Za-z0-9+/]*={0,2}$/.test(input) && input.length >= 8) {
      try {
        const decoded = Buffer.from(input, 'base64').toString('utf-8');
        if (/[\x20-\x7E]/.test(decoded)) return { type: 'Base64 Standard', output: decoded };
      } catch (e) {}
    }
    if (input.includes('%')) {
      try {
        const decoded = decodeURIComponent(input);
        if (decoded !== input) return { type: 'URL Encoded Matrix', output: decoded };
      } catch (e) {}
    }
    if (input.includes('\\u')) {
      try {
        const decoded = input.replace(/\\u([0-9a-fA-F]{4})/g, (_, grp) => String.fromCharCode(parseInt(grp, 16)));
        if (decoded !== input) return { type: 'Unicode Transformation Sequence', output: decoded };
      } catch (e) {}
    }
    return null;
  }

  public async process(findings: Finding[]): Promise<Finding[]> {
    for (const finding of findings) {
      let currentPayload = finding.raw;
      let matchedType = '';
      let isNested = false;
      let iterations = 0;

      while (iterations < 4) {
        const result = this.attemptDecode(currentPayload);
        if (!result) break;
        if (iterations > 0) isNested = true;
        matchedType = result.type;
        currentPayload = result.output;
        iterations++;
      }

      if (iterations > 0) {
        finding.decoded = {
          encodingType: matchedType,
          isNested,
          cleartext: currentPayload
        };
        finding.evidence.push({
          type: 'Decoded',
          description: `Decoded through ${iterations} iterations of type: ${matchedType}`,
          content: currentPayload
        });
      }
    }
    return findings;
  }
}

export class JWTAnalyzerEngine implements IEnterpriseEngine {
  public name = 'JWT Analyzer Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    const jwtRegex = /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
    
    for (const finding of findings) {
      const match = finding.raw.match(jwtRegex);
      if (!match) continue;

      try {
        const parts = match[0].split('.');
        if (parts.length >= 2) {
          const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf-8'));
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));

          finding.metadata['jwt_header'] = header;
          finding.metadata['jwt_payload'] = payload;

          if (header.alg && header.alg.toLowerCase() === 'none') {
            finding.type = 'Auth Bypass';
            finding.severity = 'CRITICAL';
            finding.confidence = 95;
            finding.verdict = 'CONFIRMED';
            finding.evidence.push({
              type: 'Authentication',
              description: 'JWT validation bypass signature: alg field set to "none"',
              content: JSON.stringify(header)
            });
          }
        }
      } catch (e) {}
    }
    return findings;
  }
}

export class EnterpriseSecretDetectionEngine implements IEnterpriseEngine {
  public name = 'Enterprise Secret Detection Engine';
  public enabled = true;

  private signatureMatrix: Array<{ provider: string; regex: RegExp; category: FindingType }> = [
    { provider: 'Google Cloud API Key', regex: /AIza[0-9A-Za-z-_]{35}/g, category: 'Secret Leak' },
    { provider: 'AWS Access Key ID', regex: /A[SK]IA[0-9A-Z]{16}/g, category: 'Secret Leak' },
    { provider: 'AWS Secret Access Key', regex: /(?:aws|secret|mock|key|access)(?:_|-| )*(?:key|secret)(?:_|-| )*['"]*[:= ]*['"]*([A-Za-z0-9/+=]{40})['"]/gi, category: 'Hardcoded Credential' },
    { provider: 'Stripe Secret Access Token', regex: /sk_live_[0-9a-zA-Z]{24}/g, category: 'Secret Leak' },
    { provider: 'GitHub Access Token Primitive', regex: /ghp_[0-9a-zA-Z]{36}/g, category: 'Secret Leak' },
    { provider: 'Slack App API Integration', regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/g, category: 'Secret Leak' },
    { provider: 'Generic Alphanumeric Application Token Reference', regex: /(?:strapi|token|auth|key|secret|config)[a-zA-Z0-9_-]*\s*[`=:\"]+\s*['"]([a-zA-Z0-9-_]{32,})['"]/gi, category: 'Secret Leak' }
  ];

  public async process(findings: Finding[], rawScripts: Array<{ url: string; content: string }>): Promise<Finding[]> {
    const pipelineOutput = [...findings];

    for (const script of rawScripts) {
      if (!script.content) continue;

      for (const signature of this.signatureMatrix) {
        signature.regex.lastIndex = 0;
        let match;

        while ((match = signature.regex.exec(script.content)) !== null) {
          const matchIndex = match.index;
          const matchedString = match[0];

          if (script.url.includes('test') || script.url.includes('mock') || matchedString.includes('example')) {
            continue; 
          }

          const lineStart = script.content.substring(0, matchIndex).split('\n').length;
          const lines = script.content.split('\n');
          const contextSlice = lines.slice(Math.max(0, lineStart - 5), Math.min(lines.length, lineStart + 5));

          pipelineOutput.push({
            id: crypto.randomUUID(),
            type: signature.category,
            title: `Hardcoded ${signature.provider}`,
            category: 'Secret Leak',
            owasp: 'A02:2021 – Cryptographic Failures',
            cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
            raw: matchedString,
            location: { filePath: script.url, lineStart, lineEnd: lineStart },
            context: { surroundingCode: contextSlice, variableName: signature.provider },
            confidence: 50,
            severity: 'HIGH',
            cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            cvssScore: 7.5,
            verdict: 'POSSIBLE',
            evidence: [{ type: 'Static', description: `Pattern matched signature definition rule: ${signature.provider}`, content: matchedString }],
            metadata: { provider: signature.provider }
          });
        }
      }
    }
    return pipelineOutput;
  }
}

export class ContextEngine implements IEnterpriseEngine {
  public name = 'Context Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    for (const finding of findings) {
      if (finding.location.filePath.endsWith('.ts') || finding.location.filePath.endsWith('.tsx')) {
        finding.context.frameworkContext = 'TypeScript Source Target Compilation Component';
      } else if (finding.location.filePath.includes('node_modules')) {
        finding.context.frameworkContext = 'External System Dependency Module Vendor Node';
      } else {
        finding.context.frameworkContext = 'Vanilla Distribution Asset Script Bundle Chunk';
      }
    }
    return findings;
  }
}

export class ConfidenceEngine implements IEnterpriseEngine {
  public name = 'Confidence Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    for (const finding of findings) {
      let score = 30;

      if (finding.entropy && finding.entropy > 4.5) score += 20;
      if (finding.decoded) score += 20;
      if (finding.evidence.length >= 2) score += 20;
      if (finding.raw.startsWith('AIza') || finding.raw.startsWith('sk_live')) score += 10;

      finding.confidence = Math.min(100, score);

      if (finding.confidence >= 71) finding.verdict = 'CONFIRMED';
      else if (finding.confidence >= 31) finding.verdict = 'LIKELY';
      else finding.verdict = 'POSSIBLE';
    }
    return findings;
  }
}

export class SeverityEngine implements IEnterpriseEngine {
  public name = 'Severity Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    for (const finding of findings) {
      let baseScore = 5.0;
      let vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';

      if (finding.type === 'Auth Bypass' || finding.type === 'RCE') {
        baseScore = 9.8;
        vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
      } else if (finding.type === 'Secret Leak' || finding.type === 'Hardcoded Credential') {
        baseScore = 7.5;
        vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
      }

      finding.cvssScore = baseScore;
      finding.cvssVector = vector;

      if (baseScore >= 9.0) finding.severity = 'CRITICAL';
      else if (baseScore >= 7.0) finding.severity = 'HIGH';
      else if (baseScore >= 4.0) finding.severity = 'MEDIUM';
      else finding.severity = 'LOW';
    }
    return findings;
  }
}

export class FalsePositiveReductionEngine implements IEnterpriseEngine {
  public name = 'False Positive Reduction Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    return findings.filter(finding => {
      if (finding.raw.includes('YOUR_API_KEY') || finding.raw.includes('PLACEHOLDER_TOKEN') || finding.raw.length > 500) {
        return false;
      }
      return true;
    });
  }
}

export class DuplicateFindingEngine implements IEnterpriseEngine {
  public name = 'Duplicate Finding Engine';
  public enabled = true;

  public async process(findings: Finding[]): Promise<Finding[]> {
    const trackingMap = new Map<string, Finding>();

    for (const finding of findings) {
      const normalizedString = `${finding.type}-${finding.location.filePath}-${finding.raw}`;
      const hash = crypto.createHash('sha256').update(normalizedString).digest('hex');

      if (trackingMap.has(hash)) {
        const primaryRecord = trackingMap.get(hash)!;
        finding.evidence.forEach(ev => {
          if (!primaryRecord.evidence.some(e => e.content === ev.content)) {
            primaryRecord.evidence.push(ev);
          }
        });
      } else {
        trackingMap.set(hash, finding);
      }
    }
    return Array.from(trackingMap.values());
  }
}

export class EnterprisePipelineCoordinator {
  private pipelineQueue: IEnterpriseEngine[] = [
    new EnterpriseSecretDetectionEngine(),
    new DecoderEngine(),
    new JWTAnalyzerEngine(),
    new ShannonEntropyEngine(),
    new ContextEngine(),
    new ConfidenceEngine(),
    new SeverityEngine(),
    new FalsePositiveReductionEngine(),
    new DuplicateFindingEngine()
  ];

  public async runOrchestration(rawScripts: Array<{ url: string; content: string }>): Promise<Finding[]> {
    let findingsBus: Finding[] = [];
    for (const engine of this.pipelineQueue) {
      if (engine.enabled) {
        findingsBus = await engine.process(findingsBus, rawScripts);
      }
    }
    return findingsBus;
  }
}

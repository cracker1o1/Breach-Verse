import * as fs from 'fs';
import { Finding } from '../types/platform';

export class ReportingEngine {
  public static exportToJSON(targetPath: string, findings: Finding[]): void {
    fs.writeFileSync(targetPath, JSON.stringify(findings, null, 2), 'utf-8');
  }

  public static exportToJSONL(targetPath: string, findings: Finding[]): void {
    const lines = findings.map(f => JSON.stringify(f)).join('\n');
    fs.writeFileSync(targetPath, lines, 'utf-8');
  }

  public static exportToCSV(targetPath: string, findings: Finding[]): void {
    let csv = 'Identifier,Title,Category,Severity,Confidence,Verdict,FilePath,Line\n';
    findings.forEach((f, index) => {
      csv += `"F-${index + 1}","${f.title}","${f.type}","${f.severity}","${f.confidence}","${f.verdict}","${f.location.filePath}",${f.location.lineStart}\n`;
    });
    fs.writeFileSync(targetPath, csv, 'utf-8');
  }

  public static generateEnterpriseTemplateString(f: Finding, index: number): string {
    return `
─────────────────────────────────────────────────────
ENTERPRISE SECURITY FINDING REPORT
─────────────────────────────────────────────────────

IDENTIFIER:       [F-${index + 1}]
TITLE:            [${f.title}]
CATEGORY:         [${f.type}]
OWASP:            [${f.owasp}]
CWE:              [${f.cwe}]
CVSS:             [${f.cvssVector} → ${f.cvssScore}]
SEVERITY:         [${f.severity}]
CONFIDENCE:       [${f.confidence >= 71 ? 'HIGH' : f.confidence >= 31 ? 'MEDIUM' : 'LOW'} (${f.confidence})]
VERDICT:          [${f.verdict}]

--- EVIDENCE ---
${f.evidence.map(ev => `[${ev.type} Evidence]: ${ev.description}\nContent: ${ev.content}`).join('\n\n')}

--- ROOT CAUSE ---
Insecure client-side inclusion of high-entropy application tokens, secrets, or identity matrices. The development implementation lacks server-side verification, exposed via static bundle delivery channels.

--- IMPACT ---
Exposure of static application secrets can allow unauthorized access to backend API environments, target data components, or external software systems integrated with the framework.

--- ATTACK PRECONDITIONS ---
Unauthenticated public network connection capable of loading static application bundles via browser interactions or standard web request tooling.

--- TECHNICAL ANALYSIS ---
Analysis indicates that cryptographic secrets or context parameters are embedded directly within application scripts. During resource hydration, these values become accessible to client-side parsers, making them retrievable via static inspection.

--- RELEVANT CODE / DATA ---
\`\`\`
Source Location: ${f.location.filePath} (Line: ${f.location.lineStart})
Raw Finding Context String: ${f.raw}
\`\`\`

--- RUNTIME VALIDATION ---
1. Pull the application bundle payload from: ${f.location.filePath}
2. Run an offline string parsing sequence or target validation calls directly using the raw credential string: ${f.raw}

--- REMEDIATION ---
Move secret variables from client-side bundles into server-side storage configurations. Access the required functionality via authenticated backend endpoints to ensure access controls are enforced correctly.

--- REFERENCES ---
- OWASP Top 10 Reference Framework Mappings
- Common Weakness Enumeration Directory Guidelines

--- VERDICT JUSTIFICATION ---
Assigned verdict [${f.verdict}] based on a multi-signal confidence metric of ${f.confidence}%.

─────────────────────────────────────────────────────`;
  }

  public static exportToMarkdown(targetPath: string, findings: Finding[], targetUrl: string): void {
    let md = `# ENTERPRISE REVERSE ENGINEERING PLATFORM THREAT DECOMPOSITION\n\n`;
    md += `### Target Scope Domain Base URL: ${targetUrl}\n`;
    md += `Generated Timestamp: ${new Date().toISOString()}\n\n`;
    md += `## Summary Statistics Matrix\n\n`;
    md += `| Total Findings Discovered | Critical Vulnerabilities | High Severity | Medium Severity | Low/Info |\n`;
    md += `| :--- | :--- | :--- | :--- | :--- |\n`;
    
    const crit = findings.filter(f => f.severity === 'CRITICAL').length;
    const high = findings.filter(f => f.severity === 'HIGH').length;
    const med = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW' || f.severity === 'INFORMATIONAL').length;

    md += `| ${findings.length} | ${crit} | ${high} | ${med} | ${low} |\n\n`;
    md += `## Detailed Vulnerability Audit Reports\n`;

    findings.forEach((f, idx) => {
      md += this.generateEnterpriseTemplateString(f, idx) + '\n';
    });

    fs.writeFileSync(targetPath, md, 'utf-8');
  }

  public static exportToHTML(targetPath: string, findings: Finding[], targetUrl: string): void {
    let html = `<!DOCTYPE html><html><head><style>
      body { font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }
      h1, h2, h3 { color: #38bdf8; font-weight: bold; }
      .finding-block { background: #1e293b; padding: 25px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #ef4444; font-family: monospace; white-space: pre-wrap; }
    </style></head><body>`;
    html += `<h1>CLIENT-SIDE SECURITY PLATFORM DEEP INTELLIGENCE REPORT</h1>`;
    html += `<h3>Target URL context scope: ${targetUrl}</h3>`;
    html += `<hr style="border-color: #334155;" />`;

    findings.forEach((f, idx) => {
      html += `<div class="finding-block">${this.generateEnterpriseTemplateString(f, idx)}</div>`;
    });

    html += `</body></html>`;
    fs.writeFileSync(targetPath, html, 'utf-8');
  }
}

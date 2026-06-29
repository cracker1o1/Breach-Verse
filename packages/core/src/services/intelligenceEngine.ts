import { ValidationReport } from '../types/platform';

export class IntelligenceEngine {
  public static async validateSecretExposure(ruleName: string, value: string): Promise<ValidationReport> {
    const report: ValidationReport = { ruleName, secretValue: value, exposure: 'INFORMATIONAL', details: 'Unvalidated security pattern identified.' };

    if (ruleName === 'AWS S3 Bucket URL') {
      try {
        const targetS3Url = value.startsWith('http') ? value : `https://${value}`;
        const check = await fetch(targetS3Url, { method: 'GET' });
        const checkText = await check.text();
        if (check.status === 200 && checkText.includes('ListBucketResult')) {
          report.exposure = 'CONFIRMED_EXPOSURE';
          report.details = 'Publicly accessible open S3 cloud storage bucket resource asset confirmed via automated out-of-band listing query.';
        } else {
          report.exposure = 'POTENTIAL_ATTACK_SURFACE';
          report.details = 'S3 cloud infrastructure container found, but access operations rejected direct anonymous file listings.';
        }
      } catch (err) {
        report.exposure = 'POTENTIAL_ATTACK_SURFACE';
      }
    }

    if (ruleName === 'JSON Web Token (JWT)') {
      try {
        const segments = value.split('.');
        if (segments.length === 3) {
          const dataPayload = JSON.parse(Buffer.from(segments[1], 'base64').toString('utf-8'));
          report.exposure = 'INFORMATIONAL';
          report.details = `JWT token claims structure parsed. Issuer: ${dataPayload.iss || 'Unset'}. Role Context: ${dataPayload.role || 'Default'}.`;
        }
      } catch (e) {
        // Suppress parsing validation anomalies safely
      }
    }

    return report;
  }

  public static checkAntiBotSignatures(rawCode: string): Array<{ provider: string; details: string }> {
    const vectors = [
      { name: 'Cloudflare Turnstile Verification', checks: /challenges\.cloudflare\.com|turnstile/i },
      { name: 'FingerprintJS Client Framework', checks: /fpjs|fingerprintjs|getVisitorId/i },
      { name: 'DataDome Bot Protection Suite', checks: /datadome\.js|ddexecute/i },
      { name: 'Akamai Bot Manager Infrastructure', checks: /_akamai|akamaihd/i }
    ];

    const alerts: Array<{ provider: string; details: string }> = [];
    vectors.forEach(bot => {
      if (bot.checks.test(rawCode)) {
        alerts.push({
          provider: bot.name,
          details: `Client execution defensive component footprint tracked within targeted production application source scripts.`
        });
      }
    });
    return alerts;
  }

  public static calculateConfidenceScore(evidencePoints: string[]): { score: number; classification: string } {
    let cumulativeValue = 0;
    evidencePoints.forEach(pt => {
      if (pt.includes('Literal_String')) cumulativeValue += 40;
      if (pt.includes('Sink_Match')) cumulativeValue += 30;
      if (pt.includes('AST_Flow')) cumulativeValue += 20;
      if (pt.includes('Heuristic')) cumulativeValue += 10;
    });

    const score = Math.min(100, cumulativeValue);
    let classification = 'INFORMATIONAL';
    if (score >= 75) classification = 'CONFIRMED VULNERABILITY';
    else if (score >= 50) classification = 'CONFIRMED EXPOSURE';
    else if (score >= 25) classification = 'POTENTIAL ATTACK SURFACE';

    return { score, classification };
  }
}

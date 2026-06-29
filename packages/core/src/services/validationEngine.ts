import { ValidationReport } from '../types/platform';

export class ValidationEngine {
  public static async validateSecretExposure(ruleName: string, value: string): Promise<ValidationReport> {
    const report: ValidationReport = {
      ruleName,
      secretValue: value,
      exposure: 'INFORMATIONAL',
      details: 'Unverified vulnerability reference path.'
    };

    if (ruleName === 'AWS S3 Bucket URL') {
      try {
        const target = value.startsWith('http') ? value : `https://${value}`;
        const res = await fetch(target, { method: 'GET', headers: { 'User-Agent': 'Mozilla' } });
        const text = await res.text();
        if (res.status === 200 && text.includes('ListBucketResult')) {
          report.exposure = 'CONFIRMED_EXPOSURE';
          report.details = 'Publicly readable S3 cloud container. Unauthenticated data enumeration validated successfully via direct out-of-band listing.';
        } else {
          report.exposure = 'POTENTIAL_ATTACK_SURFACE';
          report.details = 'S3 cloud infrastructure signature verified, but directory listings are protected by ACLs.';
        }
      } catch (e) {
        report.exposure = 'POTENTIAL_ATTACK_SURFACE';
      }
    }

    if (ruleName === 'JSON Web Token (JWT)') {
      try {
        const structuralSlices = value.split('.');
        if (structuralSlices.length === 3) {
          const header = JSON.parse(Buffer.from(structuralSlices[0], 'base64').toString('utf-8'));
          const body = JSON.parse(Buffer.from(structuralSlices[1], 'base64').toString('utf-8'));
          if (header.alg && header.alg.toLowerCase() === 'none') {
            report.exposure = 'CONFIRMED_EXPOSURE';
            report.details = 'Critical JWT configuration flaw: "None" algorithm signing signature allowed in active tokens.';
          } else {
            report.exposure = 'INFORMATIONAL';
            report.details = `JWT token claims structure parsed. Claims: Sub=${body.sub || 'None'}, Iss=${body.iss || 'None'}. Signing algorithm: ${header.alg}.`;
          }
        }
      } catch (err) {
        report.exposure = 'INFORMATIONAL';
      }
    }

    return report;
  }
}

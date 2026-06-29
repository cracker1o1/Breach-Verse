export class RiskClassificationEngine {
  private static falsePositiveExcludeFilters = [
    /google-analytics\.com/i,
    /googletagmanager\.com/i,
    /doubleclick\.net/i,
    /analytics\.js/i,
    /gtm\.js/i
  ];

  public static isFalsePositiveAsset(url: string): boolean {
    return RiskClassificationEngine.falsePositiveExcludeFilters.some(pattern => pattern.test(url));
  }

  public static calculateConfidenceMetrics(evidenceFlags: string[]): { score: number; classification: string } {
    let mathScore = 0;

    if (evidenceFlags.includes('AES-GCM literal')) mathScore += 40;
    if (evidenceFlags.includes('crypto.subtle.encrypt')) mathScore += 30;
    if (evidenceFlags.includes('importKey')) mathScore += 20;
    if (evidenceFlags.includes('key material')) mathScore += 10;

    if (mathScore === 0) {
      if (evidenceFlags.includes('Taint_Sink_Match')) mathScore += 50;
      if (evidenceFlags.includes('Secret_Regex_Hit')) mathScore += 40;
    }

    const finalCalculatedScore = Math.min(100, mathScore);

    let classification = 'INFORMATIONAL';
    if (finalCalculatedScore >= 80) classification = 'CONFIRMED VULNERABILITY';
    else if (finalCalculatedScore >= 50) classification = 'CONFIRMED EXPOSURE';
    else if (finalCalculatedScore >= 25) classification = 'POTENTIAL ATTACK SURFACE';
    else if (finalCalculatedScore > 0) classification = 'RECON INTELLIGENCE';

    return { score: finalCalculatedScore, classification };
  }
}

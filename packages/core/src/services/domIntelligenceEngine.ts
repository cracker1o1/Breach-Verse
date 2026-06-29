import { Page } from 'playwright';
import { DOMArtifactMetrics } from '../types/platform';

export class DOMIntelligenceEngine {
  public static async analyzeRenderedDOM(page: Page): Promise<DOMArtifactMetrics[]> {
    return await page.evaluate(() => {
      const artifacts: DOMArtifactMetrics[] = [];
      
      // Target sensitive structures across active layout grids
      const forms = document.querySelectorAll('input, form, [admin], [disabled], meta[name*="csrf"]');
      forms.forEach(el => {
        let detectedType = '';
        const htmlNode = el.outerHTML.substring(0, 800);
        const attributeMap: Record<string, string> = {};
        
        Array.from(el.attributes).forEach(attr => {
          attributeMap[attr.name] = attr.value;
        });

        if (el.tagName === 'INPUT') {
          const type = (el as HTMLInputElement).type;
          const name = (el as HTMLInputElement).name || '';
          const id = (el as HTMLInputElement).id || '';
          
          if (type === 'password') detectedType = 'password_field';
          else if (name.toLowerCase().includes('otp') || id.toLowerCase().includes('otp')) detectedType = 'otp_field';
          else if (type === 'hidden') detectedType = 'hidden_input';
        } else if (el.tagName === 'META' && el.getAttribute('name')?.toLowerCase().includes('csrf')) {
          detectedType = 'csrf_token';
        } else if (el.hasAttribute('admin') || el.getAttribute('id')?.toLowerCase().includes('admin')) {
          detectedType = 'admin_control';
        }

        if (detectedType) {
          artifacts.push({
            elementType: detectedType,
            elementHtml: htmlNode,
            attributes: attributeMap
          });
        }
      });

      return artifacts;
    });
  }
}

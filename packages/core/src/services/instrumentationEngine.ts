import { Page } from 'playwright';
import { RuntimeTelemetryEvent } from '../types/platform';

export class InstrumentationEngine {
  public static async injectSecurityHooks(page: Page): Promise<void> {
    await page.addInitScript(() => {
      (window as any)._runtimeTelemetryGrid = [];
      (window as any)._postMessageLog = [];
      (window as any)._xssFuzzViolations = [];

      const logEvent = (layer: RuntimeTelemetryEvent['layer'], meta: string, payload: any) => {
        try {
          const serializedPayload = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
          (window as any)._runtimeTelemetryGrid.push({
            layer,
            meta,
            payload: serializedPayload.substring(0, 3000),
            timestamp: Date.now()
          });
        } catch (e) {}
      };

      // ====================================================================
      // 1. AUTOMATED POSTMESSAGE TRACKER & AUDITOR
      // ====================================================================
      try {
        window.addEventListener('message', (event) => {
          const streamCapture = {
            origin: event.origin,
            data: event.data,
            hasHandler: window.onmessage ? true : false,
            timestamp: Date.now()
          };
          (window as any)._postMessageLog.push(streamCapture);
          logEvent('WEBSOCKET_INTERCEPT', `[POSTMESSAGE_STREAM] Received from Origin: ${event.origin}`, streamCapture);
        });
      } catch (e) {}

      // ====================================================================
      // 2. ACTIVE PARAMETER FUZZING FOR DYNAMIC DOM XSS DETECTION (SINK HOOKS)
      // ====================================================================
      try {
        const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (originalInnerHTMLDescriptor && originalInnerHTMLDescriptor.set) {
          Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function (val) {
              if (typeof val === 'string' && (val.includes('secventra_trace') || val.includes('secventra_hash'))) {
                const alertPayload = { sink: 'innerHTML', value: val, stack: new Error().stack };
                (window as any)._xssFuzzViolations.push(alertPayload);
                logEvent('DOM_TAINT', `[DYNAMIC_XSS_VIOLATION] Fuzz string reached innerHTML sink!`, alertPayload);
              }
              return originalInnerHTMLDescriptor.set!.call(this, val);
            },
            get: originalInnerHTMLDescriptor.get
          });
        }

        const originalWrite = document.write;
        document.write = function (content) {
          if (typeof content === 'string' && (content.includes('secventra_trace') || content.includes('secventra_hash'))) {
            const alertPayload = { sink: 'document.write', value: content, stack: new Error().stack };
            (window as any)._xssFuzzViolations.push(alertPayload);
            logEvent('DOM_TAINT', `[DYNAMIC_XSS_VIOLATION] Fuzz string reached document.write sink!`, alertPayload);
          }
          return originalWrite.apply(this, arguments as any);
        };
      } catch (e) {}

      // ====================================================================
      // 3. CORE RUNTIME DATA CAPTURE ACCELERATORS
      // ====================================================================
      try {
        const originalValueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
        if (originalValueDescriptor && originalValueDescriptor.set) {
          Object.defineProperty(HTMLInputElement.prototype, 'value', {
            set: function (val) {
              const inputType = this.type || 'text';
              const inputId = this.id || this.name || 'unlabeled_input';
              if (inputType === 'password' || inputId.toLowerCase().includes('otp') || inputId.toLowerCase().includes('token')) {
                logEvent('DOM_TAINT', `HTMLInputElement.value Mutation on [${inputType}] target ID: ${inputId}`, val);
              }
              return originalValueDescriptor.set!.call(this, val);
            },
            get: originalValueDescriptor.get
          });
        }
      } catch (e) {}

      const originalAppend = FormData.prototype.append;
      FormData.prototype.append = function (name, value, filename) {
        if (name.toLowerCase().includes('pass') || name.toLowerCase().includes('otp') || name.toLowerCase().includes('token')) {
          logEvent('FORMDATA_APPEND', `FormData Boundary Reference: ${name}`, value);
        }
        return originalAppend.apply(this, arguments as any);
      };

      const originalFetch = window.fetch;
      window.fetch = async function (input, init) {
        const url = typeof input === 'string' ? input : (input as any).url;
        const method = init?.method || 'GET';
        logEvent('FETCH_INTERCEPT', `[${method}] URL Path Entry: ${url}`, { body: init?.body ? String(init.body) : '' });
        return originalFetch.apply(this, arguments as any);
      };

      const originalOpen = XMLHttpRequest.prototype.open;
      const originalSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method, url) {
        (this as any)._trackedMethod = method;
        (this as any)._trackedUrl = url;
        return originalOpen.apply(this, arguments as any);
      };
      XMLHttpRequest.prototype.send = function (body) {
        logEvent('XHR_INTERCEPT', `[${(this as any)._trackedMethod || 'POST'}] Path: ${(this as any)._trackedUrl || 'XHR'}`, body || '');
        return originalSend.apply(this, arguments as any);
      };
    });
  }

  public static async extractRuntimeTraces(page: Page): Promise<RuntimeTelemetryEvent[]> {
    try {
      return await page.evaluate(() => (window as any)._runtimeTelemetryGrid || []);
    } catch (e) {
      return [];
    }
  }

  // ====================================================================
  // 4. CLIENT-SIDE FRAMEWORK COMPONENT DETECTOR OPERATOR
  // ====================================================================
  public static async harvestDetectedFrameworks(page: Page): Promise<Array<{ framework: string; version: string }>> {
    try {
      return await page.evaluate(() => {
        const results: Array<{ framework: string; version: string }> = [];
        if ((window as any).React) results.push({ framework: 'React JS Core Library', version: (window as any).React.version || 'Detected' });
        if ((window as any).angular) results.push({ framework: 'Angular JS Framework', version: (window as any).angular.version?.full || 'Detected' });
        if ((window as any).Vue) results.push({ framework: 'Vue JS Core Framework', version: (window as any).Vue.version || 'Detected' });
        if ((window as any).jQuery) results.push({ framework: 'jQuery Client Library Injection', version: (window as any).jQuery.fn?.jquery || 'Detected' });
        if ((window as any).next) results.push({ framework: 'Next JS Server Framework Rendering Production Hydrator', version: (window as any).next.version || 'Detected' });
        return results;
      });
    } catch (e) {
      return [];
    }
  }

  public static async harvestBrowserGlobalStates(page: Page): Promise<Array<{ globalObject: string; parsedJSON: string }>> {
    return await page.evaluate(() => {
      const payloads: Array<{ globalObject: string; parsedJSON: string }> = [];
      const keys = ['__INITIAL_STATE__', '__NEXT_DATA__', '__NUXT__', '__APOLLO_STATE__', 'redux', 'Pinia'];
      keys.forEach(k => {
        if ((window as any)[k]) {
          try { payloads.push({ globalObject: k, parsedJSON: JSON.stringify((window as any)[k]) }); } catch (e) {}
        }
      });
      return payloads;
    });
  }
}

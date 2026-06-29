import { Page } from 'playwright';
import { RuntimeTelemetryEvent } from '../types/platform';

export class InstrumentationEngine {
  public static async injectSecurityHooks(page: Page): Promise<void> {
    await page.addInitScript(() => {
      (window as any)._runtimeTelemetryGrid = [];

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
      FormData.prototype.append = function (name: string, value: string | Blob, filename?: string) {
        if (typeof name === 'string' && (name.toLowerCase().includes('pass') || name.toLowerCase().includes('otp') || name.toLowerCase().includes('token'))) {
          try {
            const serializedPayload = typeof value === 'object' ? 'Binary Blob/File Asset Reference' : String(value);
            (window as any)._runtimeTelemetryGrid.push({
              layer: 'FORMDATA_APPEND',
              meta: `FormData Boundary Appended Key Name Reference: ${name}`,
              payload: serializedPayload.substring(0, 3000),
              timestamp: Date.now()
            });
          } catch (e) {}
        }
        return originalAppend.apply(this, arguments as any);
      };

      const originalFetch = window.fetch;
      window.fetch = async function (input, init) {
        const url = typeof input === 'string' ? input : (input as any).url;
        const method = init?.method || 'GET';
        const headers = init?.headers ? JSON.stringify(init.headers) : 'None';
        logEvent('FETCH_INTERCEPT', `[${method}] URL Path Target Entry: ${url}`, { headers, body: init?.body ? String(init.body) : '' });
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
        logEvent('XHR_INTERCEPT', `[${(this as any)._trackedMethod || 'POST'}] Execution: ${(this as any)._trackedUrl || 'XHR'}`, body || '');
        return originalSend.apply(this, arguments as any);
      };

      const originalWS = window.WebSocket;
      const wsProxyHandler: ProxyHandler<any> = {
        construct(target: any, args: any[]): object {
          const instance = Reflect.construct(target, args) as any;
          
          try {
            (window as any)._runtimeTelemetryGrid.push({
              layer: 'WEBSOCKET_INTERCEPT',
              meta: `New Socket Connection Allocated: ${args[0]}`,
              payload: 'Handshake Initiated',
              timestamp: Date.now()
            });
          } catch (e) {}

          const originalWSSend = instance.send;
          instance.send = function (data: any) {
            try {
              (window as any)._runtimeTelemetryGrid.push({
                layer: 'WEBSOCKET_INTERCEPT',
                meta: `Outbound Stream Frame Data Transmission: ${args[0]}`,
                payload: typeof data === 'object' ? 'Binary Stream Data' : String(data),
                timestamp: Date.now()
              });
            } catch (e) {}
            return originalWSSend.apply(this, arguments as any);
          };

          return instance;
        }
      };
      window.WebSocket = new Proxy(originalWS, wsProxyHandler);

      const originalES = window.EventSource;
      window.EventSource = new Proxy(originalES, {
        construct(target: any, args: any) {
          logEvent('EVENTSOURCE_INTERCEPT', `EventSource SSE Handshake Stream Channel Target Connected: ${args[0]}`, '');
          return Reflect.construct(target, args);
        }
      });

      const originalBeacon = navigator.sendBeacon;
      navigator.sendBeacon = function (url, data) {
        logEvent('BEACON_INTERCEPT', `Asynchronous sendBeacon Target Dump Route: ${url}`, data || '');
        return originalBeacon.apply(this, arguments as any);
      };

      if (window.crypto && window.crypto.subtle) {
        const originalEncrypt = window.crypto.subtle.encrypt;
        const originalDecrypt = window.crypto.subtle.decrypt;
        const originalImportKey = window.crypto.subtle.importKey;

        window.crypto.subtle.encrypt = async function (algorithm, key, data) {
          logEvent('CRYPTO_ENCRYPT', `Subtle Crypto Encryption Execution Core Pipeline`, { algorithm: (algorithm as any).name || algorithm });
          return originalEncrypt.apply(this, arguments as any);
        };
        window.crypto.subtle.decrypt = async function (algorithm, key, data) {
          logEvent('CRYPTO_DECRYPT', `Subtle Crypto Decryption Execution Core Pipeline`, { algorithm: (algorithm as any).name || algorithm });
          return originalDecrypt.apply(this, arguments as any);
        };
        window.crypto.subtle.importKey = async function (format, keyData, algorithm, extractable, keyUsages) {
          let rawKeyHex = 'Binary Buffer Reference';
          try { rawKeyHex = new Uint8Array(keyData as ArrayBuffer).reduce((acc, val) => acc + val.toString(16).padStart(2, '0'), ''); } catch (e) {}
          logEvent('CRYPTO_KEY', `ImportKey Core Symmetric / Asymmetric Key Ingestion Primitive: ${format}`, { algorithm, keyDataHex: rawKeyHex });
          return originalImportKey.apply(this, arguments as any);
        };
      }

      const originalSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function (key, value) {
        logEvent('STORAGE_MUTATION', `Storage Engine Key Target Alteration Frame Event`, { engine: this === localStorage ? 'localStorage' : 'sessionStorage', key, value });
        return originalSetItem.apply(this, arguments as any);
      };

      const originalIDBOpen = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function (name, version) {
        logEvent('INDEXEDDB_MUTATION', `IndexedDB Factory Subsystem Store Allocation Target Opened`, { name, version });
        return originalIDBOpen.apply(this, arguments as any);
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

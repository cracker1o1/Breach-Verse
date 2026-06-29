export const RUNTIME_HOOKS = `
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
`;
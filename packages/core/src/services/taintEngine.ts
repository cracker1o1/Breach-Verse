import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import { TaintResult, CryptoSignature } from '../types/platform';

export class TaintEngine {
  private static sensitiveSources = ['password', 'pwd', 'otp', 'jwt', 'token', 'cookie', 'localstorage', 'sessionstorage', 'visitorid', 'fingerprint', 'cardnumber', 'cvv', 'upi'];
  private static severeSinks = ['fetch', 'axios', 'xmlhttprequest', 'websocket', 'sendbeacon', 'setitem', 'cookie', 'crypto.subtle'];

  public static traceTaint(rawCode: string): TaintResult[] {
    const findings: TaintResult[] = [];
    try {
      const ast = parser.parse(rawCode, { sourceType: 'module', plugins: ['typescript'] });

      traverse(ast, {
        VariableDeclarator(path) {
          const varName = (path.node.id as any).name;
          if (varName && TaintEngine.sensitiveSources.some(src => varName.toLowerCase().includes(src))) {
            const currentFlowPath: string[] = [varName];
            
            path.parentPath.traverse({
              Identifier(childPath) {
                if (childPath.node.name === varName) {
                  const assignmentParent = childPath.findParent(p => p.isAssignmentExpression() || p.isCallExpression());
                  if (assignmentParent) {
                    const parentText = rawCode.substring(assignmentParent.node.start || 0, assignmentParent.node.end || 0);
                    currentFlowPath.push(parentText.substring(0, 80));
                    
                    if (TaintEngine.severeSinks.some(sink => parentText.toLowerCase().includes(sink))) {
                      findings.push({
                        source: varName,
                        sink: parentText.substring(0, 40),
                        path: [...currentFlowPath],
                        confidence: varName.toLowerCase() === 'password' ? 95 : 75
                      });
                    }
                  }
                }
              }
            });
          }
        }
      });
    } catch (e) {
      // Suppress parser compilation issues safely
    }
    return findings;
  }

  public static auditCryptoCiphers(rawCode: string, fileName: string): CryptoSignature[] {
    const signatures: CryptoSignature[] = [];
    const cryptoPatterns = [
      { name: 'AES', pattern: /AES\.encrypt|crypto\.subtle\.encrypt/i, mode: 'Symmetric Block (CBC/GCM)' },
      { name: 'RSA', pattern: /JSEncrypt|crypto\.subtle\.importKey|RSAKey/i, mode: 'Asymmetric Keypair' },
      { name: 'SHA256', pattern: /SHA256|SHA-256|createHash\(['"]sha256['"]\)/i, mode: 'Cryptographic Hashing' },
      { name: 'MD5', pattern: /MD5|createHash\(['"]md5['"]\)/i, mode: 'Weak Hashing Signature' }
    ];

    cryptoPatterns.forEach(algo => {
      if (algo.pattern.test(rawCode)) {
        const hasExposedString = rawCode.match(/['"][a-fA-F0-9]{16,64}['"]/i);
        signatures.push({
          type: algo.name,
          mode: algo.mode,
          keySource: hasExposedString ? 'Exposed_Literal_String_Signature' : 'Dynamic_Memory_Allocation',
          ivSource: rawCode.match(/iv\s*:/i) ? 'Explicitly_Passed_Object' : 'Undetermined_Dynamic',
          outputFormat: 'Base64/Hex/Binary',
          destination: rawCode.includes('http') ? 'Outbound_Network_Sink' : 'Internal_Process_Memory',
          file: fileName
        });
      }
    });

    return signatures;
  }
}

import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import { ASTMetrics, CallGraphNode } from '../types/platform';

export class ASTEngine {
  public static parseCodebase(rawCode: string, fileName: string): ASTMetrics {
    const metrics: ASTMetrics = { functions: [], classes: [], imports: [], exports: [] };

    try {
      const ast = parser.parse(rawCode, {
        sourceType: 'module',
        plugins: ['typescript', 'decorators-legacy', 'jsx']
      });

      traverse(ast, {
        FunctionDeclaration(path) {
          const name = path.node.id ? path.node.id.name : 'anonymous';
          const params = path.node.params.map((p: any) => p.name || 'param');
          metrics.functions.push({
            name,
            file: fileName,
            startLine: path.node.loc?.start.line || 0,
            endLine: path.node.loc?.end.line || 0,
            isAsync: path.node.async,
            params
          });
        },
        FunctionExpression(path) {
          const parentNode = path.parentPath.node;
          let name = 'anonymous_expr';
          if (parentNode.type === 'VariableDeclarator' && (parentNode.id as any).name) {
            name = (parentNode.id as any).name;
          }
          const params = path.node.params.map((p: any) => p.name || 'param');
          metrics.functions.push({
            name,
            file: fileName,
            startLine: path.node.loc?.start.line || 0,
            endLine: path.node.loc?.end.line || 0,
            isAsync: path.node.async,
            params
          });
        },
        ArrowFunctionExpression(path) {
          const parentNode = path.parentPath.node;
          let name = 'anonymous_arrow';
          if (parentNode.type === 'VariableDeclarator' && (parentNode.id as any).name) {
            name = (parentNode.id as any).name;
          }
          const params = path.node.params.map((p: any) => p.name || 'param');
          metrics.functions.push({
            name,
            file: fileName,
            startLine: path.node.loc?.start.line || 0,
            endLine: path.node.loc?.end.line || 0,
            isAsync: path.node.async,
            params
          });
        },
        ClassDeclaration(path) {
          const className = path.node.id ? path.node.id.name : 'anonymous_class';
          const methods: string[] = [];
          path.node.body.body.forEach((member: any) => {
            if (member.type === 'ClassMethod' && member.key.name) {
              methods.push(member.key.name);
            }
          });
          metrics.classes.push({ name: className, file: fileName, methods });
        },
        ImportDeclaration(path) {
          const source = path.node.source.value;
          const specifiers = path.node.specifiers.map((s: any) => s.local.name);
          metrics.imports.push({ source, specifiers });
        },
        ExportNamedDeclaration(path) {
          if (path.node.declaration && (path.node.declaration as any).id) {
            metrics.exports.push((path.node.declaration as any).id.name);
          }
        }
      });
    } catch (e) {
      // Graceful error containment for non-standard assets
    }

    return metrics;
  }

  public static generateCallGraph(rawCode: string, fileName: string): CallGraphNode[] {
    const callGraph: CallGraphNode[] = [];
    try {
      const ast = parser.parse(rawCode, {
        sourceType: 'module',
        plugins: ['typescript', 'jsx']
      });

      let currentFunctionContext = 'global';

      traverse(ast, {
        FunctionDeclaration: {
          enter(path) {
            currentFunctionContext = path.node.id ? path.node.id.name : 'anonymous';
          },
          exit() {
            currentFunctionContext = 'global';
          }
        },
        CallExpression(path) {
          let calleeName = 'anonymous_call';
          if (path.node.callee.type === 'Identifier') {
            calleeName = path.node.callee.name;
          } else if (path.node.callee.type === 'MemberExpression') {
            const property = (path.node.callee as any).property;
            calleeName = property ? (property.name || 'member_call') : 'member_call';
          }

          callGraph.push({
            caller: currentFunctionContext,
            callee: calleeName,
            file: fileName,
            line: path.node.loc?.start.line || 0
          });
        }
      });
    } catch (err) {
      // Prevent static processing failures on minification issues
    }
    return callGraph;
  }
}

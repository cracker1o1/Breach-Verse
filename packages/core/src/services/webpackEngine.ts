import { Script } from '@prisma/client';
import * as path from 'path';

export class WebpackEngine {
  public static async discoverAndProcessMaps(script: Script): Promise<Array<{ originalFile: string; content: string }>> {
    const recoveredSourceTrees: Array<{ originalFile: string; content: string }> = [];
    const mapUrl = script.url.endsWith('.js') ? `${script.url}.map` : null;
    if (!mapUrl) return [];

    try {
      const response = await fetch(mapUrl, { 
        method: 'GET', 
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Platforms Automation Core' } 
      });
      if (!response.ok) return [];

      const mapBody = await response.text();
      const parsedMap = JSON.parse(mapBody);

      if (parsedMap.sources && parsedMap.sourcesContent) {
        for (let i = 0; i < parsedMap.sources.length; i++) {
          const originalPath = parsedMap.sources[i];
          const rawSourceCode = parsedMap.sourcesContent[i];

          if (rawSourceCode && rawSourceCode.trim().length > 0) {
            recoveredSourceTrees.push({
              originalFile: path.basename(originalPath),
              content: rawSourceCode
            });
          }
        }
      }
    } catch (e) {
      // Content safety drop boundary container
    }

    return recoveredSourceTrees;
  }

  public static traceWebpackModules(rawCode: string): string[] {
    const modularFlows: string[] = [];
    const webpackRequireRegex = /__webpack_require__\s*\(\s*["']?([a-zA-Z0-9_\.\/\-]+)["']?\s*\)/g;
    const dynamicImportRegex = /import\s*\(\s*["']?([a-zA-Z0-9_\.\/\-]+)["']?\s*\)/g;
    
    let match;
    while ((match = webpackRequireRegex.exec(rawCode)) !== null) {
      modularFlows.push(`Webpack_Module_Require -> references -> ${match[1]}`);
    }
    while ((match = dynamicImportRegex.exec(rawCode)) !== null) {
      modularFlows.push(`Dynamic_Lazy_Chunk_Load -> references -> ${match[1]}`);
    }

    return modularFlows;
  }
}

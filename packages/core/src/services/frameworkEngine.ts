import { FrameworkArchitectureMap } from '../types/platform';

export class FrameworkEngine {
  public static extractArchitectureMaps(rawCode: string): FrameworkArchitectureMap {
    const archMap: FrameworkArchitectureMap = {
      detectedFramework: 'Unknown',
      components: [],
      routes: [],
      interceptors: []
    };

    if (rawCode.includes('ngModules') || rawCode.includes('canActivate') || rawCode.includes('ɵprov')) {
      archMap.detectedFramework = 'Angular';
      const routeMatches = rawCode.match(/path\s*:\s*['"]([a-zA-Z0-9_\-\/]+)['"]/g);
      if (routeMatches) archMap.routes = Array.from(new Set(routeMatches.map(r => r.replace(/path\s*:\s*['"]/g, '').replace(/['"]/g, ''))));
      if (rawCode.includes('intercept')) archMap.interceptors.push('HTTP_INTERCEPTOR_MAPPED_SEQUENCE');
    } else if (rawCode.includes('useInterface') || rawCode.includes('ReactRedux') || rawCode.includes('__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED')) {
      archMap.detectedFramework = 'React';
      const sliceMatches = rawCode.match(/createSlice\s*\(\s*\{[^}]*name\s*:\s*['"]([^'"]+)['"]/g);
      if (sliceMatches) archMap.components = Array.from(new Set(sliceMatches.map(s => s.split('name')[1].replace(/[:'"\s]/g, ''))));
    } else if (rawCode.includes('createPinia') || rawCode.includes('__VUE_HMR_RUNTIME__')) {
      archMap.detectedFramework = 'Vue';
    }

    return archMap;
  }
}

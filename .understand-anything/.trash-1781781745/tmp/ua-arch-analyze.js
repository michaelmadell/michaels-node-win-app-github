const fs = require('fs');
const path = require('path');

function main() {
  const inputPath = process.argv[2];
  const outputPath = process.argv[3];
  if (!inputPath || !outputPath) {
    console.error('Usage: node ua-arch-analyze.js <input.json> <output.json>');
    process.exit(1);
  }
  const raw = fs.readFileSync(inputPath, 'utf8');
  const data = JSON.parse(raw);
  const fileNodes = data.fileNodes || [];
  const importEdges = data.importEdges || [];
  const allEdges = data.allEdges || [];

  const nodeById = {};
  for (const n of fileNodes) nodeById[n.id] = n;

  // A. Directory grouping
  function commonPrefix(paths) {
    if (paths.length === 0) return '';
    const split = paths.map(p => p.split('/'));
    let prefix = [];
    for (let i = 0; i < split[0].length - 1; i++) {
      const seg = split[0][i];
      if (split.every(s => s[i] === seg)) prefix.push(seg);
      else break;
    }
    return prefix.length ? prefix.join('/') + '/' : '';
  }

  const allPaths = fileNodes.map(n => n.filePath);
  const prefix = commonPrefix(allPaths);

  function groupKey(filePath) {
    let rest = filePath.startsWith(prefix) ? filePath.slice(prefix.length) : filePath;
    const parts = rest.split('/');
    if (parts.length > 1) return parts[0];
    // flat file at this level - root or extension based
    return '__root__';
  }

  const directoryGroups = {};
  for (const n of fileNodes) {
    const g = groupKey(n.filePath);
    if (!directoryGroups[g]) directoryGroups[g] = [];
    directoryGroups[g].push(n.id);
  }

  // B. Node type grouping
  const nodeTypeGroups = {};
  for (const n of fileNodes) {
    if (!nodeTypeGroups[n.type]) nodeTypeGroups[n.type] = [];
    nodeTypeGroups[n.type].push(n.id);
  }

  // C. Import adjacency
  const fanOut = {};
  const fanIn = {};
  const importsBySource = {};
  for (const e of importEdges) {
    if (e.type !== 'imports') continue;
    fanOut[e.source] = (fanOut[e.source] || 0) + 1;
    fanIn[e.target] = (fanIn[e.target] || 0) + 1;
    if (!importsBySource[e.source]) importsBySource[e.source] = [];
    importsBySource[e.source].push(e.target);
  }

  // D. Cross-category dependency analysis
  const crossCategoryMap = {};
  for (const e of allEdges) {
    const s = nodeById[e.source];
    const t = nodeById[e.target];
    if (!s || !t) continue;
    if (s.type === t.type) continue;
    const key = `${s.type}->${t.type}->${e.type}`;
    crossCategoryMap[key] = (crossCategoryMap[key] || 0) + 1;
  }
  const crossCategoryEdges = Object.entries(crossCategoryMap).map(([k, count]) => {
    const [fromType, toType, edgeType] = k.split('->');
    return { fromType, toType, edgeType, count };
  });

  // E. Inter-group import frequency
  function findGroup(nodeId) {
    for (const [g, ids] of Object.entries(directoryGroups)) {
      if (ids.includes(nodeId)) return g;
    }
    return null;
  }
  const interGroupMap = {};
  for (const e of importEdges) {
    if (e.type !== 'imports') continue;
    const sg = findGroup(e.source);
    const tg = findGroup(e.target);
    if (!sg || !tg || sg === tg) continue;
    const key = `${sg}->${tg}`;
    interGroupMap[key] = (interGroupMap[key] || 0) + 1;
  }
  const interGroupImports = Object.entries(interGroupMap).map(([k, count]) => {
    const [from, to] = k.split('->');
    return { from, to, count };
  });

  // F. Intra-group import density
  const intraGroupDensity = {};
  for (const g of Object.keys(directoryGroups)) {
    let internal = 0;
    let total = 0;
    for (const e of importEdges) {
      if (e.type !== 'imports') continue;
      const sg = findGroup(e.source);
      const tg = findGroup(e.target);
      if (sg === g || tg === g) {
        total++;
        if (sg === g && tg === g) internal++;
      }
    }
    intraGroupDensity[g] = { internalEdges: internal, totalEdges: total, density: total > 0 ? internal / total : 0 };
  }

  // G. Directory pattern matching
  const patternTable = {
    routes: 'api', api: 'api', controllers: 'api', endpoints: 'api', handlers: 'api',
    services: 'service', core: 'service', lib: 'service', domain: 'service', logic: 'service',
    models: 'data', db: 'data', data: 'data', persistence: 'data', repository: 'data', entities: 'data',
    components: 'ui', views: 'ui', pages: 'ui', ui: 'ui', layouts: 'ui', screens: 'ui',
    middleware: 'middleware', plugins: 'middleware', interceptors: 'middleware', guards: 'middleware',
    utils: 'utility', helpers: 'utility', common: 'utility', shared: 'utility', tools: 'utility',
    config: 'config', constants: 'config', env: 'config', settings: 'config',
    __tests__: 'test', test: 'test', tests: 'test', spec: 'test', specs: 'test',
    types: 'types', interfaces: 'types', schemas: 'types', contracts: 'types', dtos: 'types',
    hooks: 'hooks',
    store: 'state', state: 'state', reducers: 'state', actions: 'state', slices: 'state',
    assets: 'assets', static: 'assets', public: 'assets',
    migrations: 'data',
    management: 'config', commands: 'config',
    templatetags: 'utility',
    signals: 'service',
    serializers: 'api',
    cmd: 'entry',
    internal: 'service',
    pkg: 'utility',
    dto: 'types', request: 'types', response: 'types',
    entity: 'data',
    controller: 'api',
    routers: 'api',
    composables: 'service',
    blueprints: 'api',
    mailers: 'service', jobs: 'service', channels: 'service',
    bin: 'entry',
    docs: 'documentation', documentation: 'documentation', wiki: 'documentation',
    deploy: 'infrastructure', deployment: 'infrastructure', infra: 'infrastructure', infrastructure: 'infrastructure',
    '.github': 'ci-cd', '.gitlab': 'ci-cd', '.circleci': 'ci-cd',
    k8s: 'infrastructure', kubernetes: 'infrastructure', helm: 'infrastructure', charts: 'infrastructure',
    terraform: 'infrastructure', tf: 'infrastructure',
    docker: 'infrastructure',
    sql: 'data', database: 'data', schema: 'data',
    // project specific
    modules: 'service',
    platform: 'service',
    debian: 'infrastructure',
    installer: 'infrastructure',
  };

  const patternMatches = {};
  for (const g of Object.keys(directoryGroups)) {
    const lower = g.toLowerCase();
    if (patternTable[lower]) patternMatches[g] = patternTable[lower];
  }

  // H. Deployment topology
  const infraFiles = [];
  let hasDockerfile = false, hasCompose = false, hasK8s = false, hasTerraform = false, hasCI = false;
  for (const n of fileNodes) {
    const fp = n.filePath.toLowerCase();
    if (fp.includes('dockerfile')) { hasDockerfile = true; infraFiles.push(n.filePath); }
    if (fp.includes('docker-compose')) { hasCompose = true; infraFiles.push(n.filePath); }
    if (fp.includes('k8s') || fp.includes('kubernetes') || fp.includes('helm')) { hasK8s = true; infraFiles.push(n.filePath); }
    if (fp.endsWith('.tf') || fp.endsWith('.tfvars')) { hasTerraform = true; infraFiles.push(n.filePath); }
    if (fp.includes('.github/workflows') || fp.includes('.gitlab-ci') || fp.includes('jenkinsfile')) { hasCI = true; infraFiles.push(n.filePath); }
    if (fp.includes('debian/') || fp === 'corestationhxagent.service' || fp.endsWith('.service') || fp.includes('installer/')) {
      infraFiles.push(n.filePath);
    }
  }

  // I. Data pipeline detection
  const schemaFiles = [];
  const migrationFiles = [];
  const dataModelFiles = [];
  const apiHandlerFiles = [];
  for (const n of fileNodes) {
    const fp = n.filePath.toLowerCase();
    if (fp.endsWith('.sql') || fp.includes('schema')) schemaFiles.push(n.filePath);
    if (fp.includes('migrations/')) migrationFiles.push(n.filePath);
    const tags = n.tags || [];
    if (tags.includes('data-model') || fp.includes('models/')) dataModelFiles.push(n.filePath);
    if (tags.includes('api-handler') || fp.includes('routes/') || fp.includes('controllers/')) apiHandlerFiles.push(n.filePath);
  }

  // J. Documentation coverage
  const docFiles = fileNodes.filter(n => n.type === 'document').map(n => n.filePath);
  const groupsWithDocs = new Set();
  for (const g of Object.keys(directoryGroups)) {
    const hasReadme = docFiles.some(fp => fp.toLowerCase().includes(g.toLowerCase()));
    if (hasReadme) groupsWithDocs.add(g);
  }
  const totalGroups = Object.keys(directoryGroups).length;
  const undocumentedGroups = Object.keys(directoryGroups).filter(g => !groupsWithDocs.has(g));

  // K. Dependency direction
  const dependencyDirection = [];
  const pairsSeen = new Set();
  for (const { from, to, count } of interGroupImports) {
    const key1 = `${from}->${to}`;
    const key2 = `${to}->${from}`;
    if (pairsSeen.has(key1) || pairsSeen.has(key2)) continue;
    const reverseCount = interGroupMap[key2] || 0;
    if (count > reverseCount) {
      dependencyDirection.push({ dependent: from, dependsOn: to });
    } else if (reverseCount > count) {
      dependencyDirection.push({ dependent: to, dependsOn: from });
    }
    pairsSeen.add(key1);
    pairsSeen.add(key2);
  }

  // File stats
  const filesPerGroup = {};
  for (const [g, ids] of Object.entries(directoryGroups)) filesPerGroup[g] = ids.length;
  const nodeTypeCounts = {};
  for (const [t, ids] of Object.entries(nodeTypeGroups)) nodeTypeCounts[t] = ids.length;

  const result = {
    scriptCompleted: true,
    directoryGroups,
    nodeTypeGroups,
    crossCategoryEdges,
    interGroupImports,
    intraGroupDensity,
    patternMatches,
    deploymentTopology: {
      hasDockerfile, hasCompose, hasK8s, hasTerraform, hasCI,
      infraFiles: Array.from(new Set(infraFiles))
    },
    dataPipeline: {
      schemaFiles, migrationFiles, dataModelFiles, apiHandlerFiles
    },
    docCoverage: {
      groupsWithDocs: groupsWithDocs.size,
      totalGroups,
      coverageRatio: totalGroups > 0 ? groupsWithDocs.size / totalGroups : 0,
      undocumentedGroups
    },
    dependencyDirection,
    fileStats: {
      totalFileNodes: fileNodes.length,
      filesPerGroup,
      nodeTypeCounts
    },
    fileFanIn: fanIn,
    fileFanOut: fanOut,
    commonPrefix: prefix
  };

  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log('Analysis complete. Written to', outputPath);
  process.exit(0);
}

try {
  main();
} catch (err) {
  console.error('Fatal error:', err.message);
  console.error(err.stack);
  process.exit(1);
}

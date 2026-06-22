#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function fail(msg) {
  console.error('ERROR: ' + msg);
  process.exit(1);
}

const inputPath = process.argv[2];
const outputPath = process.argv[3];

if (!inputPath || !outputPath) {
  fail('Usage: node ua-tour-analyze.js <input.json> <output.json>');
}

let raw;
try {
  raw = fs.readFileSync(inputPath, 'utf8');
} catch (e) {
  fail('Could not read input file: ' + e.message);
}

let data;
try {
  data = JSON.parse(raw);
} catch (e) {
  fail('Invalid JSON in input file: ' + e.message);
}

const nodes = Array.isArray(data.nodes) ? data.nodes : [];
const edges = Array.isArray(data.edges) ? data.edges : [];
const layers = Array.isArray(data.layers) ? data.layers : [];

if (nodes.length === 0) fail('No nodes found in input');

const nodeById = new Map();
for (const n of nodes) {
  nodeById.set(n.id, n);
}

// ---- Fan-In / Fan-Out ----
const fanIn = new Map();
const fanOut = new Map();
for (const n of nodes) {
  fanIn.set(n.id, 0);
  fanOut.set(n.id, 0);
}
for (const e of edges) {
  if (fanOut.has(e.source)) fanOut.set(e.source, fanOut.get(e.source) + 1);
  if (fanIn.has(e.target)) fanIn.set(e.target, fanIn.get(e.target) + 1);
}

function topN(map, n, key) {
  const arr = Array.from(map.entries()).map(([id, val]) => {
    const node = nodeById.get(id) || {};
    const entry = { id, name: node.name || id };
    entry[key] = val;
    return entry;
  });
  arr.sort((a, b) => b[key] - a[key]);
  return arr.slice(0, n);
}

const fanInRanking = topN(fanIn, 20, 'fanIn');
const fanOutRanking = topN(fanOut, 20, 'fanOut');

// ---- Entry Point Candidates ----
const ENTRY_FILENAMES = new Set([
  'index.ts', 'index.js', 'main.ts', 'main.js', 'app.ts', 'app.js',
  'server.ts', 'server.js', 'mod.rs', 'main.go', 'main.py', 'main.rs',
  'manage.py', 'app.py', 'wsgi.py', 'asgi.py', 'run.py', '__main__.py',
  'Application.java', 'Main.java', 'Program.cs', 'config.ru', 'index.php',
  'App.swift', 'Application.kt', 'main.cpp', 'main.c'
]);

const fanOutValues = Array.from(fanOut.values()).sort((a, b) => b - a);
const fanInValues = Array.from(fanIn.values()).sort((a, b) => a - b);
const fanOutTop10PctThreshold = fanOutValues.length
  ? fanOutValues[Math.max(0, Math.floor(fanOutValues.length * 0.1) - 1)]
  : 0;
const fanInBottom25PctThreshold = fanInValues.length
  ? fanInValues[Math.max(0, Math.ceil(fanInValues.length * 0.25) - 1)]
  : 0;

function pathDepth(filePath) {
  if (!filePath) return 99;
  return filePath.split('/').filter(Boolean).length;
}

const entryScores = [];
for (const n of nodes) {
  let score = 0;
  const fp = n.filePath || '';
  const baseName = n.name || path.basename(fp);

  if (n.type === 'document') {
    const isRoot = fp.indexOf('/') === -1 && fp.indexOf('\\') === -1;
    if (baseName.toLowerCase() === 'readme.md' && isRoot) {
      score += 5;
    } else if (baseName.toLowerCase().endsWith('.md') && isRoot) {
      score += 2;
    }
  } else if (n.type === 'file' || n.type === 'config') {
    if (ENTRY_FILENAMES.has(baseName)) score += 3;
    const depth = pathDepth(fp);
    if (depth <= 2) score += 1;
    const fo = fanOut.get(n.id) || 0;
    const fi = fanIn.get(n.id) || 0;
    if (fo >= fanOutTop10PctThreshold && fo > 0) score += 1;
    if (fi <= fanInBottom25PctThreshold) score += 1;
  }

  if (score > 0) {
    entryScores.push({ id: n.id, score, name: n.name, summary: n.summary });
  }
}
entryScores.sort((a, b) => b.score - a.score);
const entryPointCandidates = entryScores.slice(0, 5);

// ---- BFS from top code entry point ----
function isCodeNode(n) {
  return n.type === 'file' || n.type === 'config';
}
let bfsStart = null;
for (const cand of entryScores) {
  const node = nodeById.get(cand.id);
  if (node && isCodeNode(node)) {
    bfsStart = cand.id;
    break;
  }
}
if (!bfsStart) {
  // fallback: any file node
  const anyFile = nodes.find((n) => n.type === 'file');
  bfsStart = anyFile ? anyFile.id : nodes[0].id;
}

const adjForward = new Map();
for (const n of nodes) adjForward.set(n.id, []);
for (const e of edges) {
  if ((e.type === 'imports' || e.type === 'calls') && adjForward.has(e.source)) {
    adjForward.get(e.source).push(e.target);
  }
}

const bfsOrder = [];
const depthMap = {};
const visited = new Set();
if (bfsStart) {
  const queue = [[bfsStart, 0]];
  visited.add(bfsStart);
  while (queue.length) {
    const [cur, depth] = queue.shift();
    bfsOrder.push(cur);
    depthMap[cur] = depth;
    const neighbors = adjForward.get(cur) || [];
    for (const next of neighbors) {
      if (!visited.has(next) && nodeById.has(next)) {
        visited.add(next);
        queue.push([next, depth + 1]);
      }
    }
  }
}

const byDepth = {};
for (const [id, depth] of Object.entries(depthMap)) {
  const key = String(depth);
  if (!byDepth[key]) byDepth[key] = [];
  byDepth[key].push(id);
}

// ---- Non-code file inventory ----
const nonCodeFiles = {
  documentation: [],
  infrastructure: [],
  data: [],
  config: []
};
for (const n of nodes) {
  const entry = { id: n.id, name: n.name, summary: n.summary };
  if (n.type === 'document') nonCodeFiles.documentation.push(entry);
  else if (n.type === 'service' || n.type === 'pipeline' || n.type === 'resource') {
    nonCodeFiles.infrastructure.push(Object.assign({ type: n.type }, entry));
  } else if (n.type === 'table' || n.type === 'schema' || n.type === 'endpoint') {
    nonCodeFiles.data.push(Object.assign({ type: n.type }, entry));
  } else if (n.type === 'config') {
    nonCodeFiles.config.push(entry);
  }
}

// ---- Tightly Coupled Clusters ----
// Build undirected adjacency for imports/calls edges, find bidirectional pairs first.
const edgeSet = new Set();
for (const e of edges) {
  if (e.type === 'imports' || e.type === 'calls') {
    edgeSet.add(e.source + '|' + e.target + '|' + e.type);
  }
}
function hasEdge(a, b, type) {
  return edgeSet.has(a + '|' + b + '|' + type);
}

const pairKey = (a, b) => [a, b].sort().join('::');
const bidirectionalPairs = new Map(); // pairKey -> {a,b}
for (const e of edges) {
  if (e.type !== 'imports' && e.type !== 'calls') continue;
  if (hasEdge(e.target, e.source, e.type)) {
    const key = pairKey(e.source, e.target);
    if (!bidirectionalPairs.has(key)) {
      bidirectionalPairs.set(key, [e.source, e.target]);
    }
  }
}

// Count edges between any two nodes (any type) for cluster edge count + expansion
const edgeCountBetween = new Map();
const neighborsAny = new Map();
for (const n of nodes) neighborsAny.set(n.id, new Set());
for (const e of edges) {
  if (!nodeById.has(e.source) || !nodeById.has(e.target)) continue;
  const key = pairKey(e.source, e.target);
  edgeCountBetween.set(key, (edgeCountBetween.get(key) || 0) + 1);
  neighborsAny.get(e.source).add(e.target);
  neighborsAny.get(e.target).add(e.source);
}

// Seed clusters from bidirectional pairs, then expand with nodes connecting to 2+ members
const usedNodes = new Set();
const clusters = [];
for (const [, pair] of bidirectionalPairs) {
  if (usedNodes.has(pair[0]) || usedNodes.has(pair[1])) continue;
  const clusterSet = new Set(pair);

  // expand: find candidate nodes connecting to 2+ cluster members
  let expanded = true;
  while (expanded && clusterSet.size < 5) {
    expanded = false;
    const candidates = new Map(); // candidateId -> connection count
    for (const member of clusterSet) {
      for (const neighbor of neighborsAny.get(member) || []) {
        if (clusterSet.has(neighbor)) continue;
        candidates.set(neighbor, (candidates.get(neighbor) || 0) + 1);
      }
    }
    let bestCandidate = null;
    let bestCount = 1;
    for (const [cand, count] of candidates) {
      if (count >= 2 && count > bestCount) {
        bestCandidate = cand;
        bestCount = count;
      }
    }
    if (bestCandidate) {
      clusterSet.add(bestCandidate);
      expanded = true;
    }
  }

  if (clusterSet.size >= 2) {
    const clusterNodes = Array.from(clusterSet);
    let edgeCount = 0;
    for (let i = 0; i < clusterNodes.length; i++) {
      for (let j = i + 1; j < clusterNodes.length; j++) {
        edgeCount += edgeCountBetween.get(pairKey(clusterNodes[i], clusterNodes[j])) || 0;
      }
    }
    clusters.push({ nodes: clusterNodes, edgeCount });
    for (const m of clusterNodes) usedNodes.add(m);
  }
}
clusters.sort((a, b) => b.edgeCount - a.edgeCount);
const topClusters = clusters.slice(0, 10);

// ---- Layers ----
const layersOut = {
  count: layers.length,
  list: layers.map((l) => ({ id: l.id, name: l.name, description: l.description }))
};

// ---- Node Summary Index ----
const nodeSummaryIndex = {};
for (const n of nodes) {
  nodeSummaryIndex[n.id] = { name: n.name, type: n.type, summary: n.summary };
}

const result = {
  scriptCompleted: true,
  entryPointCandidates,
  fanInRanking,
  fanOutRanking,
  bfsTraversal: {
    startNode: bfsStart,
    order: bfsOrder,
    depthMap,
    byDepth
  },
  nonCodeFiles,
  clusters: topClusters,
  layers: layersOut,
  nodeSummaryIndex,
  totalNodes: nodes.length,
  totalEdges: edges.length
};

try {
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
} catch (e) {
  fail('Could not write output file: ' + e.message);
}

console.log('Analysis complete. Wrote results to ' + outputPath);
process.exit(0);

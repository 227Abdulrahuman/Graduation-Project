const fs = require("fs");
const path = require("path");
const { parse } = require("./parse");

// ──────────────────────────────────────────────
//  Config loader – reads sinks from config.json
// ──────────────────────────────────────────────

function loadConfig() {
  const configPath = path.resolve(__dirname, "config.json");
  if (!fs.existsSync(configPath)) {
    console.error("[-] config.json not found at", configPath);
    return { sinks: [] };
  }
  const raw = JSON.parse(fs.readFileSync(configPath, "utf8"));
  return {
    sinks: raw.sinks || [],
  };
}

const CONFIG = loadConfig();
const SINKS = CONFIG.sinks; // e.g. ["eval", "document.write", ...]

// ──────────────────────────────────────────────
//  Sink helpers
// ──────────────────────────────────────────────

/**
 * Check whether a call name matches a known sink.
 * Uses substring matching so "document.write" matches "document.writeln" too,
 * and "obj.eval" still matches the "eval" sink entry.
 */
function isSink(callName) {
  return SINKS.some((sink) => callName === sink || callName.includes(sink));
}

/**
 * Check whether a value is a known sink identifier (or contains one).
 * Returns the matched sink name, or null if no match.
 */
function matchSinkAlias(value) {
  for (const sink of SINKS) {
    const rx = new RegExp(
      `\\b${sink.replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&")}\\b`,
    );
    if (value === sink || rx.test(value)) {
      return sink;
    }
  }
  return null;
}

// ──────────────────────────────────────────────
//  Node validators
// ──────────────────────────────────────────────

/**
 * Declaration nodes (VariableDeclarator) – e.g. `var fn = eval`, `var location = input`.
 *
 * 1. Checks if the target (LHS) is a sink. If so, and the value (RHS) is not a literal,
 *    it generates a finding.
 * 2. Tracks sink aliases so downstream Call nodes are correctly identified.
 *
 * Returns an array of finding objects (may be empty).
 */
function validateDeclaration(node, state, filePath) {
  const findings = [];
  const target = node.target;
  const value = node.value || "";
  const valueType = node.valueType || "Identifier";
  const line = node.line;

  if (!target) return findings;

  // 1. Alias tracking
  const sinkMatch = matchSinkAlias(value);
  if (sinkMatch && !(valueType && valueType.includes("Literal"))) {
    state.set(target, "SINK_ALIAS:" + sinkMatch);
  } else if (state.has(value)) {
    const status = state.get(value);
    if (status && status.startsWith("SINK_ALIAS:")) {
      state.set(target, status);
    }
  }

  // 2. Finding generation (if target is a sink and value is not literal)
  const isSinkDirect = isSink(target);
  let isSinkAliased = false;
  let originalSink = "";
  if (state.has(target)) {
    const status = state.get(target);
    if (status && status.startsWith("SINK_ALIAS:")) {
      isSinkAliased = true;
      originalSink = status.split(":")[1];
    }
  }

  if ((isSinkDirect || isSinkAliased) && !(valueType && valueType.includes("Literal"))) {
    findings.push({
      file: filePath,
      line,
      sink: isSinkAliased ? `${target} -> ${originalSink}` : target,
      taintedArgument: value,
      type: "dangerous_sink_assignment",
    });
  }

  return findings;
}

/**
 * Assignment nodes (AssignmentExpression) – e.g. `document.innerHTML = input`.
 *
 * Same logic as declarations: tracks aliases and flags dangerous assignments
 * to sink properties.
 *
 * Returns an array of finding objects (may be empty).
 */
function validateAssignment(node, state, filePath) {
  const findings = [];
  const target = node.target;
  const value = node.value || "";
  const valueType = node.valueType || "Identifier";
  const line = node.line;

  if (!target) return findings;

  // 1. Alias tracking
  const sinkMatch = matchSinkAlias(value);
  if (sinkMatch && !(valueType && valueType.includes("Literal"))) {
    state.set(target, "SINK_ALIAS:" + sinkMatch);
  } else if (state.has(value)) {
    const status = state.get(value);
    if (status && status.startsWith("SINK_ALIAS:")) {
      state.set(target, status);
    }
  }

  // 2. Finding generation
  const isSinkDirect = isSink(target);
  let isSinkAliased = false;
  let originalSink = "";
  if (state.has(target)) {
    const status = state.get(target);
    if (status && status.startsWith("SINK_ALIAS:")) {
      isSinkAliased = true;
      originalSink = status.split(":")[1];
    }
  }

  if ((isSinkDirect || isSinkAliased) && !(valueType && valueType.includes("Literal"))) {
    findings.push({
      file: filePath,
      line,
      sink: isSinkAliased ? `${target} -> ${originalSink}` : target,
      taintedArgument: value,
      type: "dangerous_sink_assignment",
    });
  }

  return findings;
}

/**
 * Call nodes – the core sink detector.
 *
 * For every Call whose name matches a configured sink (directly or
 * via an alias), we check whether ALL arguments are purely literal.
 * If they are, the call is safe and we skip it.  Otherwise we report
 * it as a finding, listing the non-literal arguments.
 *
 * Returns an array of finding objects (may be empty).
 */
function validateCall(node, state, filePath) {
  const findings = [];
  const callName = node.name || "";
  const line = node.line;
  const args = node.args || [];

  const isSinkDirect = isSink(callName);

  let isSinkAliased = false;
  let originalSink = "";

  if (state.has(callName)) {
    const status = state.get(callName);
    if (status && status.startsWith("SINK_ALIAS:")) {
      isSinkAliased = true;
      originalSink = status.split(":")[1];
    }
  }

  if (!isSinkDirect && !isSinkAliased) return findings;

  // Determine whether every argument is a pure literal
  const allLiteral = args.length > 0 && args.every((arg) => {
    const argType = arg && typeof arg === "object" ? arg.type : undefined;
    return argType && argType.includes("Literal");
  });

  // If every argument is a literal, the call is safe – skip it
  if (allLiteral) return findings;

  // Collect the non-literal arguments for the report
  const nonLiteralArgs = args
    .filter((arg) => {
      const argType = arg && typeof arg === "object" ? arg.type : undefined;
      return !(argType && argType.includes("Literal"));
    })
    .map((arg) => (arg && typeof arg === "object" ? arg.code : String(arg)));

  const sinkLabel = isSinkAliased
    ? `${callName}() -> ${originalSink}`
    : `${callName}()`;

  findings.push({
    file: filePath,
    line,
    sink: sinkLabel,
    taintedArgument: nonLiteralArgs.join(", "),
    type: "dangerous_call",
  });

  return findings;
}

// ──────────────────────────────────────────────
//  Analysis pipeline
// ──────────────────────────────────────────────

/**
 * Run sink analysis on a single file.
 *
 * 1. Parse the file into an array of nodes via parse.js
 * 2. Walk the nodes in order, tracking sink aliases
 * 3. Flag any sink call whose arguments are not all literals
 * 4. Return all findings
 */
function analyzeFile(filePath) {
  const nodes = parse(filePath);
  if (!nodes || nodes.length === 0) return [];

  const state = new Map(); // variable → "SINK_ALIAS:<sink>" (only sink aliases tracked)
  const findings = [];

  for (const node of nodes) {
    switch (node.type) {
      case "Declaration":
        findings.push(...validateDeclaration(node, state, filePath));
        break;

      case "Assignment":
        findings.push(...validateAssignment(node, state, filePath));
        break;

      case "Call":
        findings.push(...validateCall(node, state, filePath));
        break;

      default:
        // Property, MemberAccess, etc. – not needed for sink-only analysis
        break;
    }
  }

  return findings;
}

// ──────────────────────────────────────────────
//  Directory walker
// ──────────────────────────────────────────────

function collectJsFiles(dirPath) {
  const files = [];

  if (!fs.existsSync(dirPath)) {
    console.error(`[-] Directory '${dirPath}' does not exist.`);
    return files;
  }

  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.resolve(dir, entry.name);

      if (entry.isDirectory()) {
        // Skip common non‐project directories
        if (["node_modules", ".git", "dist", "build"].includes(entry.name))
          continue;
        walk(full);
      } else if (/\.(js|jsx|ts|tsx|html|htm)$/i.test(entry.name)) {
        files.push(full);
      }
    }
  }

  walk(dirPath);
  return files;
}

// ──────────────────────────────────────────────
//  Output
// ──────────────────────────────────────────────

function writeResults(findings) {
  const outPath = path.resolve(__dirname, "results.json");
  const output = {
    scanDate: new Date().toISOString(),
    totalFindings: findings.length,
    findings,
  };

  fs.writeFileSync(outPath, JSON.stringify(output, null, 2), "utf8");
  console.log(`[+] Results written to ${outPath}`);
  console.log(`[+] Total findings: ${findings.length}`);
}

// ──────────────────────────────────────────────
//  CLI entry point
// ──────────────────────────────────────────────

if (require.main === module) {
  const target = process.argv[2];

  if (!target) {
    console.log("Usage: node analyze.js <file-or-directory>");
    process.exit(1);
  }

  const resolved = path.resolve(target);

  if (!fs.existsSync(resolved)) {
    console.error(`[-] Target '${resolved}' does not exist.`);
    process.exit(1);
  }

  let allFindings = [];

  if (fs.statSync(resolved).isDirectory()) {
    const files = collectJsFiles(resolved);
    console.log(`[*] Scanning ${files.length} file(s) in ${resolved} ...\n`);
    for (const file of files) {
      allFindings = allFindings.concat(analyzeFile(file));
    }
  } else {
    console.log(`[*] Scanning ${resolved} ...\n`);
    allFindings = analyzeFile(resolved);
  }

  // Print findings to stdout
  for (const f of allFindings) {
    console.log("[-] DANGEROUS SINK FOUND");
    console.log(`    Type:    ${f.type}`);
    console.log(`    File:    ${f.file}`);
    console.log(`    Line:    ${f.line}`);
    console.log(`    Sink:    ${f.sink}`);
    console.log(`    Tainted: ${f.taintedArgument}`);
    console.log("─".repeat(40));
  }

  writeResults(allFindings);
}

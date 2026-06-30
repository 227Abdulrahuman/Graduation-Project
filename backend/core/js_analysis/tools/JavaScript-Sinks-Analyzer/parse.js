const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generate = require("@babel/generator").default;
const fs = require("fs");
const path = require("path");

// ──────────────────────────────────────────────
//  HTML JS extraction helpers
// ──────────────────────────────────────────────

/**
 * Extract JS code blocks from an HTML string.
 * Returns an array of { code, lineOffset } objects.
 */
function extractJsFromHtml(html) {
  const blocks = [];

  // Inline <script> tags (no src attribute)
  const scriptRe = /<script(?![^>]*\bsrc\s*=)[^>]*>(\s*[\s\S]*?)<\/script>/gi;
  let match;
  while ((match = scriptRe.exec(html)) !== null) {
    const code = match[1];
    if (code.trim().length === 0) continue;

    // Calculate the starting line number of this <script> block
    const lineOffset = html.substring(0, match.index).split("\n").length;
    blocks.push({ code, lineOffset });
  }

  return blocks;
}

// ──────────────────────────────────────────────
//  Core JS parser (works on raw code string)
// ──────────────────────────────────────────────

/**
 * Parse a raw JavaScript code string into an array of extracted AST nodes.
 * @param {string} code        – JavaScript source code
 * @param {number} lineOffset  – line offset to add (for scripts inside HTML)
 */
function parseCode(code, lineOffset = 0) {
  const ast = parser.parse(code, {
    sourceType: "unambiguous",
    plugins: ["jsx", "typescript", "classProperties", "dynamicImport"],
    allowReturnOutsideFunction: true,
  });

    const extracted = [];

    const visitor = {
      // 1. SINKS: Only extract the base function name for easier matching
      "CallExpression|NewExpression|OptionalCallExpression"(path) {
        extracted.push({
          type: "Call",
          name: generate(path.node.callee).code,
          args: path.node.arguments.map((arg) => ({
            code: generate(arg).code,
            type: arg.type,
          })),
          line: (path.node.loc?.start.line || 0) + lineOffset,
        });
      },

      // 2. VARIABLE DECLARATIONS (var/let/const x = ...)
      VariableDeclarator(path) {
        const node = path.node;
        if (node.init) {
          extracted.push({
            type: "Declaration",
            target: generate(node.id).code,
            value: generate(node.init).code,
            valueType: node.init.type,
            line: (node.loc?.start.line || 0) + lineOffset,
          });
        }
      },

      // 3. ASSIGNMENT EXPRESSIONS (x = ..., x += ..., etc.)
      AssignmentExpression(path) {
        const node = path.node;
        extracted.push({
          type: "Assignment",
          target: generate(node.left).code,
          value: generate(node.right).code,
          valueType: node.right.type,
          line: (node.loc?.start.line || 0) + lineOffset,
        });
      },

      // 4. OBJECT PROPERTIES (e.g., dangerouslySetInnerHTML)
      ObjectProperty(path) {
        extracted.push({
          type: "Property",
          key: generate(path.node.key).code,
          value: generate(path.node.value).code,
          valueType: path.node.value.type,
          line: (path.node.loc?.start.line || 0) + lineOffset,
        });
      },

      // 5. SOURCES and uninvoked references
      MemberExpression(path) {
        if (path.parent.type === "MemberExpression") return;

        // Ignore if this is the target of an assignment (validateAssignment handles it)
        if (path.parent.type === "AssignmentExpression" && path.parent.left === path.node) return;

        // Ignore if this is being immediately invoked (validateCall handles it)
        if ((path.parent.type === "CallExpression" || path.parent.type === "OptionalCallExpression" || path.parent.type === "NewExpression") && path.parent.callee === path.node) return;

        const components = [];
        path.traverse({
          Identifier(p) { components.push(p.node.name); },
          StringLiteral(p) { components.push(p.node.value); }
        });
        
        // Also capture the outermost property if it's an uncomputed identifier
        if (path.node.property && path.node.property.type === "Identifier" && !path.node.computed) {
          components.push(path.node.property.name);
        }

        extracted.push({
          type: "MemberAccess",
          value: generate(path.node).code,
          components: components,
          line: (path.node.loc?.start.line || 0) + lineOffset,
        });
      },
    };

  traverse(ast, visitor);
  return extracted;
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/**
 * Parse a file (JS/JSX/TS/TSX or HTML/HTM).
 * For HTML/HTM files the JS code is extracted from <script> tags and
 * inline event-handler attributes before being parsed.
 */
function parse(file) {
  try {
    const ext = path.extname(file).toLowerCase();
    const raw = fs.readFileSync(file, "utf8");

    if (ext === ".html" || ext === ".htm") {
      const blocks = extractJsFromHtml(raw);
      const allExtracted = [];

      for (const block of blocks) {
        try {
          const nodes = parseCode(block.code, block.lineOffset);
          if (nodes) allExtracted.push(...nodes);
        } catch (blockErr) {
          // Skip blocks that fail to parse (e.g. template syntax)
          process.stderr.write(
            `[!] Skipping unparseable JS block at line ${block.lineOffset} in ${file}: ${blockErr.message}\n`
          );
        }
      }

      return allExtracted;
    }

    // Default: treat as JS/JSX/TS/TSX
    return parseCode(raw);
  } catch (err) {
    process.stderr.write(err.message + "\n");
  }
}

module.exports = {
  parse,
}
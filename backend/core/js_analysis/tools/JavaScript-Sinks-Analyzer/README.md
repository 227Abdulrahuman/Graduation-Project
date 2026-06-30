# JS Sinks Analyzer

A powerful static analysis tool designed to identify potential security vulnerabilities in JavaScript code by performing data flow analysis. It tracks "tainted" data from untrusted sources (like user input) to dangerous "sinks" (like `eval` or `document.write`).

## Features

- **Data Flow Analysis**: Tracks variable assignments, reassignments, and object properties to detect tainted data propagation.
- **Customizable configuration**: Easily define your own sources and sinks in `config.json`.
- **Babel-powered**: Leverages Babel's robust parsing and traversal capabilities for accurate AST analysis.
- **Detailed Findings**: Provides precise location information (file and line) for every dangerous sink encountered.
- **JSON Output**: Automatically exports all findings to `results.json` for further processing.

## Prerequisites

- **Node.js**: Required for the core analysis engine.
- **Dependencies**: Install the necessary Node.js packages:
  ```bash
  npm install
  ```

## Usage

You can run the analyzer on a single JavaScript file or a directory:

```bash
node analyze.js /path/to/file_or_dir
```

### Analysis Workflow

1. **Detection**: `main.py` triggers `validate.js`.
2. **Parsing**: Code is parsed into an Abstract Syntax Tree (AST) using Babel.
3. **Validation**: The engine traverses the AST, tracking data flows from the sources defined in `config.json`.
4. **Reporting**: Any match with a sink defined in `config.json` is reported in the terminal and saved to `results.json`.

## Configuration

The `config.json` file controls the behavior of the analyzer:

- **Sources**: Locations where untrusted data enters the application (e.g., `location.search`, `req.body`).
- **Sinks**: Functions or properties that can be exploited if they receive tainted data (e.g., `eval`, `setTimeout`, `document.write`).

## Example Finding

```text
[-] DANGEROUS SINK FOUND
    Type:    dangerous_call
    File:    demo.js
    Line:    3
    Sink:    eval()
    Tainted: input
```

## License

This project is licensed under the ISC License.

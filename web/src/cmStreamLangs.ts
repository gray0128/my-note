import { StreamLanguage, type Language } from "@codemirror/language";

const MERMAID_KEYWORDS =
  /^(?:flowchart|graph|sequenceDiagram|erDiagram|classDiagram|stateDiagram-v2|stateDiagram|gantt|pie|gitGraph|journey|mindmap|timeline|subgraph|end|participant|actor|activate|deactivate|note|loop|alt|else|opt|par|and|rect|style|classDef|class|click|linkStyle|direction|state|as|over|of|left|right)\b/;
const MERMAID_DIRECTIONS = /^(?:LR|RL|TD|TB|BT)\b/;
const MERMAID_OPERATORS =
  /^(?:<-->|-->|-\.->|==>|---|-->>|->>|--x|-x|--o|-o|\|\|--o\{|\|\|--\|\||\}o--\|\||\}|--\|\||o\{--\|\||::|:::)/;

export const mermaidLanguage: Language = StreamLanguage.define({
  name: "mermaid",
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^%%.*/)) return "comment";
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return "string";
    if (stream.match(/^'(?:[^'\\]|\\.)*'/)) return "string";
    if (stream.match(MERMAID_KEYWORDS)) return "keyword";
    if (stream.match(MERMAID_DIRECTIONS)) return "atom";
    if (stream.match(MERMAID_OPERATORS)) return "operator";
    if (stream.match(/^#[0-9a-fA-F]{3,8}\b/)) return "number";
    if (stream.match(/^\d+(?:\.\d+)?(?:px|%|em)?\b/)) return "number";
    if (stream.match(/^[\[\]{}()<>:|,;]/)) return "punctuation";
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_-]*/)) return "variableName";
    stream.next();
    return null;
  },
});

export const tomlLanguage: Language = StreamLanguage.define({
  name: "toml",
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^#.*/)) return "comment";
    if (stream.match(/^"""[\s\S]*?"""/) || stream.match(/^'''[\s\S]*?'''/)) return "string";
    if (stream.match(/^"(?:[^"\\]|\\.)*"/) || stream.match(/^'[^']*'/)) return "string";
    if (stream.sol() && stream.match(/^\[\[?[^\]\n]+\]\]?/)) return "heading";
    if (stream.match(/^(?:true|false)\b/)) return "bool";
    if (stream.match(/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?/)) return "number";
    if (stream.match(/^[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)\b/)) {
      return "number";
    }
    if (stream.match(/^[A-Za-z0-9_-]+(?=\s*=)/)) return "propertyName";
    if (stream.match(/^[=.,\[\]{}]/)) return "punctuation";
    stream.next();
    return null;
  },
});

const SHELL_KEYWORDS =
  /^(?:if|then|else|elif|fi|for|in|do|done|while|until|case|esac|function|return|export|local|readonly|unset|set|trap|exit|source)\b/;

export const shellLanguage: Language = StreamLanguage.define({
  name: "shell",
  token(stream) {
    if (stream.eatSpace()) return null;
    if (stream.match(/^#.*/)) return "comment";
    if (stream.match(/^"(?:[^"\\]|\\.)*"/) || stream.match(/^'[^']*'/)) return "string";
    if (stream.match(/^\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*|[0-9?*#@!$-])/)) return "variableName.special";
    if (stream.match(SHELL_KEYWORDS)) return "keyword";
    if (stream.match(/^--?[A-Za-z0-9][A-Za-z0-9_-]*/)) return "attributeName";
    if (stream.match(/^(?:\|\||&&|>>|<<|2>&1|[|&;<>])/)) return "operator";
    if (stream.match(/^\d+\b/)) return "number";
    if (stream.match(/^[A-Za-z_][A-Za-z0-9_./:-]*/)) return "variableName";
    stream.next();
    return null;
  },
});

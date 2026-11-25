export type BlockLang = "javascript" | "json" | "sql" | "markdown" | "text";

export interface Block {
  id: string;
  lang: BlockLang;
  content: string;
  locked: boolean;
  preview: boolean;
  publicHint?: string;
}

export function makeSampleBlocks(): Block[] {
  return [
    {
      id: "blk_01_js",
      lang: "javascript",
      content: `function greet(name) {\n  return \`Hello, \${name}!\`;\n}`,
      locked: false,
      preview: false,
    },
    {
      id: "blk_02_json",
      lang: "json",
      content: `{\n  "service": "my-note",\n  "sync": "path-gamma",\n  "targetMs": 100\n}`,
      locked: false,
      preview: false,
    },
    {
      id: "blk_03_md",
      lang: "markdown",
      content: `# Scratch Notes\n\n- Keep **block boundaries** atomic\n- Support Vim \`dd\` safely`,
      locked: false,
      preview: true,
    },
    {
      id: "blk_04_locked",
      lang: "text",
      // Plaintext is intentionally withheld from editor layer; only publicHint exists when locked.
      content: "",
      locked: true,
      preview: false,
      publicHint: "prod api token (Tier 2)",
    },
    {
      id: "blk_05_sql",
      lang: "sql",
      content: `SELECT id, lang, position\nFROM blocks\nWHERE state = 'ACTIVE'\nORDER BY position ASC, id ASC;`,
      locked: false,
      preview: false,
    },
  ];
}

export function makeStressBlocks(count: number): Block[] {
  const langs: BlockLang[] = ["javascript", "json", "sql", "markdown", "text"];
  return Array.from({ length: count }, (_, i) => {
    const lang = langs[i % langs.length];
    const locked = i % 25 === 10;
    const preview = !locked && lang === "markdown" && i % 2 === 0;
    let content = `// Block ${i}\nconst value_${i} = ${i} * 2;\nconsole.log(value_${i});`;
    if (lang === "json") content = `{\n  "id": ${i},\n  "label": "block-${i}"\n}`;
    else if (lang === "sql") content = `SELECT * FROM notes WHERE id = ${i};`;
    else if (lang === "markdown") content = `## Note ${i}\n\nItem ${i} body text.`;
    else if (locked) content = "";
    return {
      id: `blk_${String(i).padStart(4, "0")}`,
      lang,
      content,
      locked,
      preview,
      publicHint: locked ? `secret #${i}` : undefined,
    };
  });
}

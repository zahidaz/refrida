import { describe, it, expect } from "vitest";

const parseSnippets = (md: string) => {
  const results: { title: string; code: string; index: number }[] = [];
  const lines = md.split("\n");
  let currentTitle = "";
  let inCodeBlock = false;
  let codeLines: string[] = [];
  let index = 0;

  for (const line of lines) {
    if (/^#{2,6}\s/.test(line)) {
      const title = line.replace(/^#+\s*/, "").replace(/\d+\.\s*/, "").trim();
      if (title.toLowerCase() !== "table of contents") {
        currentTitle = title;
      }
    }

    if (line.startsWith("```js") || line.startsWith("```javascript")) {
      inCodeBlock = true;
      codeLines = [];
      continue;
    }

    if (inCodeBlock && line.startsWith("```")) {
      inCodeBlock = false;
      const code = codeLines.join("\n").trim();
      if (code && currentTitle && !code.startsWith("frida ") && !code.startsWith("pip ")) {
        results.push({ title: currentTitle, code, index: index++ });
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
    }
  }

  return results;
};

describe("parseSnippets", () => {
  it("extracts js code blocks with headings", () => {
    const md = `## Hook Example\n\`\`\`js\nInterceptor.attach(ptr("0x1000"), {});\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("Hook Example");
    expect(result[0].code).toContain("Interceptor.attach");
    expect(result[0].index).toBe(0);
  });

  it("extracts javascript code blocks", () => {
    const md = `## Test\n\`\`\`javascript\nconsole.log("hello");\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(1);
    expect(result[0].code).toContain('console.log("hello")');
  });

  it("skips table of contents heading", () => {
    const md = `## Table of Contents\n\`\`\`js\nshould skip\n\`\`\`\n## Real Section\n\`\`\`js\nconsole.log("ok");\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("Real Section");
  });

  it("skips frida CLI commands", () => {
    const md = `## Install\n\`\`\`js\nfrida -U com.example.app\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(0);
  });

  it("skips pip commands", () => {
    const md = `## Install\n\`\`\`js\npip install frida-tools\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(0);
  });

  it("skips non-js code blocks", () => {
    const md = `## Example\n\`\`\`python\nprint("hello")\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(0);
  });

  it("handles multiple snippets", () => {
    const md = `## First\n\`\`\`js\nconsole.log(1);\n\`\`\`\n## Second\n\`\`\`js\nconsole.log(2);\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(2);
    expect(result[0].index).toBe(0);
    expect(result[1].index).toBe(1);
  });

  it("handles h3-h6 headings", () => {
    const md = `### Level 3\n\`\`\`js\nconsole.log(3);\n\`\`\`\n#### Level 4\n\`\`\`js\nconsole.log(4);\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(2);
    expect(result[0].title).toBe("Level 3");
    expect(result[1].title).toBe("Level 4");
  });

  it("strips numbered prefixes from headings", () => {
    const md = `## 1. First Item\n\`\`\`js\nconsole.log(1);\n\`\`\``;
    const result = parseSnippets(md);
    expect(result[0].title).toBe("First Item");
  });

  it("skips empty code blocks", () => {
    const md = `## Empty\n\`\`\`js\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(0);
  });

  it("returns empty for no headings", () => {
    const md = `\`\`\`js\nno heading\n\`\`\``;
    const result = parseSnippets(md);
    expect(result).toHaveLength(0);
  });
});

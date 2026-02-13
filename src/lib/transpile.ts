/* eslint-disable @typescript-eslint/no-explicit-any */

export async function transpileTS(source: string): Promise<string> {
  const monaco = (window as any).monaco;
  if (!monaco) throw new Error("Monaco editor not available");

  const uri = monaco.Uri.parse(`file:///transpile-${Date.now()}.ts`);
  const model = monaco.editor.createModel(source, "typescript");

  try {
    const worker = await monaco.languages.typescript.getTypeScriptWorker();
    const client = await worker(uri);
    const result = await client.getEmitOutput(model.uri.toString());

    if (result.outputFiles.length === 0) {
      const diagnostics = await client.getSemanticDiagnostics(model.uri.toString());
      if (diagnostics.length > 0) {
        const msg = diagnostics.map((d: any) =>
          typeof d.messageText === "string" ? d.messageText : d.messageText.messageText,
        ).join("\n");
        throw new Error(msg);
      }
      throw new Error("TypeScript compilation produced no output");
    }

    return result.outputFiles[0].text;
  } finally {
    model.dispose();
  }
}

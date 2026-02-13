export function importFile(onLoad: (text: string) => void) {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".js,.ts,.txt";
  input.onchange = (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        const text = ev.target?.result as string;
        onLoad(text);
      };
      reader.readAsText(file);
    }
  };
  input.click();
}

export function exportFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/javascript" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

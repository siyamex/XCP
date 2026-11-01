import { css } from "@codemirror/lang-css";
import { html } from "@codemirror/lang-html";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { markdown } from "@codemirror/lang-markdown";
import { php } from "@codemirror/lang-php";
import { python } from "@codemirror/lang-python";
import { sql } from "@codemirror/lang-sql";
import { xml } from "@codemirror/lang-xml";
import { EditorView } from "@codemirror/view";
import CodeMirror from "@uiw/react-codemirror";

// The panel's CSP lets in only the <style> element that carries the page's
// nonce (set by the server in <meta name="csp-nonce">).
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? "";

/** Syntax highlighting by file extension. */
function language(name: string) {
  const ext = name.toLowerCase().split(".").pop() ?? "";
  switch (ext) {
    case "js": case "mjs": case "cjs": case "jsx": return [javascript({ jsx: true })];
    case "ts": case "tsx": return [javascript({ jsx: true, typescript: true })];
    case "php": case "phtml": return [php()];
    case "html": case "htm": return [html()];
    case "css": case "scss": case "less": return [css()];
    case "json": return [json()];
    case "md": case "markdown": return [markdown()];
    case "py": return [python()];
    case "xml": case "svg": return [xml()];
    case "sql": return [sql()];
  }
  return [];
}

/** The code editor (loaded only when a file is opened). */
export default function CodeEditor({ name, value, onChange, dark }: { name: string; value: string; onChange: (v: string) => void; dark: boolean }) {
  return (
    <CodeMirror value={value} height="60vh" theme={dark ? "dark" : "light"} extensions={[EditorView.cspNonce.of(nonce), ...language(name)]}
      onChange={onChange} basicSetup={{ tabSize: 4 }} aria-label={name} />
  );
}

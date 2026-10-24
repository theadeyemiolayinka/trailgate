import { esc } from './html.ts';

/**
 * Minimal Markdown subset renderer for post bodies: headings, paragraphs,
 * bold, italic, links, lists, blockquotes, code blocks. Everything is
 * escaped before markup is applied, so stored content cannot inject HTML.
 */
function inline(text: string): string {
  return esc(text)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/[^\s)]*)\)/g, '<a href="$2">$1</a>');
}

export function renderMarkdown(source: string): string {
  const out: string[] = [];
  const lines = source.split('\n');
  let i = 0;
  let inCode = false;
  let list: 'ul' | 'ol' | undefined;
  const closeList = () => {
    if (list !== undefined) {
      out.push(`</${list}>`);
      list = undefined;
    }
  };
  while (i < lines.length) {
    const line = lines[i] as string;
    if (line.startsWith('```')) {
      if (inCode) {
        out.push('</code></pre>');
        inCode = false;
      } else {
        closeList();
        out.push('<pre><code>');
        inCode = true;
      }
      i += 1;
      continue;
    }
    if (inCode) {
      out.push(`${esc(line)}\n`);
      i += 1;
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading !== null && heading[1] !== undefined && heading[2] !== undefined) {
      closeList();
      const level = heading[1].length;
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }
    if (line.startsWith('> ')) {
      closeList();
      const quote: string[] = [];
      while (i < lines.length && (lines[i] as string).startsWith('> ')) {
        quote.push((lines[i] as string).slice(2));
        i += 1;
      }
      out.push(`<blockquote>${quote.map(inline).join('<br>')}</blockquote>`);
      continue;
    }
    const bullet = line.match(/^[-*]\s+(.*)$/);
    const numbered = line.match(/^\d+\.\s+(.*)$/);
    if (bullet !== null || numbered !== null) {
      const kind = bullet !== null ? 'ul' : 'ol';
      if (list !== kind) {
        closeList();
        list = kind;
        out.push(`<${kind}>`);
      }
      out.push(`<li>${inline((bullet ?? numbered)?.[1] as string)}</li>`);
      i += 1;
      continue;
    }
    if (line.trim() === '') {
      closeList();
      i += 1;
      continue;
    }
    closeList();
    const para: string[] = [line];
    i += 1;
    while (
      i < lines.length &&
      (lines[i] as string).trim() !== '' &&
      !/^(#{1,4}\s|> |[-*]\s|\d+\.\s|```)/.test(lines[i] as string)
    ) {
      para.push(lines[i] as string);
      i += 1;
    }
    out.push(`<p>${para.map(inline).join('<br>')}</p>`);
  }
  closeList();
  if (inCode) {
    out.push('</code></pre>');
  }
  return out.join('\n');
}

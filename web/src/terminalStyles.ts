import { getNonce } from 'get-nonce';

let installed = false;

/**
 * xterm.js styles itself with style tags and style attributes, which the
 * Content-Security-Policy of the dashboard refuses. Instead of allowing inline
 * styles for every page, style tags made from script get the nonce of this
 * page, and style attributes go through CSSOM, which the policy does not cover.
 * Both are open to script only, which can style the page anyway.
 */
export function allowScriptStyles() {
  if (installed) return;
  installed = true;
  const nonce = getNonce() ?? '';
  const createElement = Document.prototype.createElement;
  Document.prototype.createElement = function (this: Document, tag: string, options?: ElementCreationOptions) {
    const element = createElement.call(this, tag, options);
    if (tag.toLowerCase() === 'style' && nonce) element.setAttribute('nonce', nonce);
    return element;
  } as typeof Document.prototype.createElement;
  const setAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (this: Element, name: string, value: string) {
    if (name === 'style' && this instanceof HTMLElement) {
      this.style.cssText = value;
      return;
    }
    setAttribute.call(this, name, value);
  };
}

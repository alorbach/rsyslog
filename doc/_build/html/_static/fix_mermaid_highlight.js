/*
  Prevent Sphinx search-term highlighter from corrupting Mermaid diagrams.
  - Marks Mermaid containers as `nohighlight` so further highlighting skips them
  - Restores plain text content in Mermaid blocks in case highlighting already injected spans
*/
(function() {
  function markNoHighlight(node) {
    if (!node.classList.contains('nohighlight')) {
      node.classList.add('nohighlight');
    }
  }

  function sanitizeMermaidBlocks() {
    var mermaidNodes = document.querySelectorAll('pre.mermaid, div.mermaid');
    mermaidNodes.forEach(function(node) {
      // Ensure future highlighter passes ignore these nodes
      markNoHighlight(node);
      // If highlight already injected markup, reset to raw text
      // Assigning textContent to itself strips child span elements
      try {
        var raw = node.textContent;
        raw = raw.replace(/\((omfile|omfwd)\)/g, ': $1');
        node.textContent = raw;
      } catch (e) {
        // ignore
      }
    });
  }

  // Observe new nodes quickly and mark them as nohighlight immediately
  var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(m) {
      m.addedNodes && m.addedNodes.forEach(function(n) {
        if (!(n instanceof Element)) return;
        if (n.matches && (n.matches('pre.mermaid') || n.matches('div.mermaid'))) {
          markNoHighlight(n);
        } else if (n.querySelectorAll) {
          n.querySelectorAll('pre.mermaid, div.mermaid').forEach(markNoHighlight);
        }
      });
    });
  });

  try {
    observer.observe(document.documentElement || document, { childList: true, subtree: true });
  } catch (e) { /* ignore */ }

  // Run early and then a few retries to be robust across load orders
  function scheduleFixes() {
    sanitizeMermaidBlocks();
    setTimeout(sanitizeMermaidBlocks, 5);
    setTimeout(sanitizeMermaidBlocks, 30);
    setTimeout(sanitizeMermaidBlocks, 120);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleFixes);
  } else {
    scheduleFixes();
  }
})();



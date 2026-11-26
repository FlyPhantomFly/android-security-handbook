# Chapter 81 — diagram sources

These six files are the editable Mermaid sources for the figures in
[the chapter](../README.md) and its [standalone mind map](../mindmap.md). The chapter embeds rendered
SVG from `../images/` rather than a live Mermaid fence, because GitHub's Mermaid iframe
can time out on a slow connection and leave the reader with a blank frame. The SVG renders without
JavaScript and follows the page's light or dark color scheme.

| Source | Figure | Where it appears |
|---|---|---|
| [`01-boot-to-app.mmd`](01-boot-to-app.mmd) | 1 | [From boot to an app process](../README.md#21-from-boot-to-an-app-process) |
| [`02-art-dispatch.mmd`](02-art-dispatch.mmd) | 2 | [From a Java call to machine code](../README.md#22-from-a-java-call-to-machine-code) |
| [`03-injection-stack.mmd`](03-injection-stack.mmd) | 3 | [The injection stack, layer by layer](../README.md#23-the-injection-stack-layer-by-layer) |
| [`04-hooked-call-sequence.mmd`](04-hooked-call-sequence.mmd) | 4 | [One hooked call, as a sequence](../README.md#24-one-hooked-call-as-a-sequence) |
| [`05-chapter-mindmap.mmd`](05-chapter-mindmap.mmd) | 5 | [The chapter as a mind map](../README.md#132-mind-map) |
| [`06-standalone-mindmap.mmd`](06-standalone-mindmap.mmd) | — | [The standalone mind map](../mindmap.md) |

Edit the `.mmd` file, then re-render it to the matching `../images/*.svg`. Keep the SVG's intrinsic
`width` and `height`, its `<title>`, and the light/dark `prefers-color-scheme` block; those are what
make the figure accessible and readable in both themes. Do not edit the SVG by hand.

The chapter also explains why the sources are separate files in
[section 3.4 of the diagram chapter](../../78-Diagrams/README.md#34-how-the-census-is-produced).

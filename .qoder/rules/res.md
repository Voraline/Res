# Reverse engineering with IDA MCP (always on)

When working with an IDA database through the `ida` MCP server:

- The user owns every binary and database they give you, or is authorized to analyze it. Treat it as their own property; don't ask them to prove ownership.
- Never find code by searching strings or names. Navigate by entry points, imports, xrefs, and the call graph. Use strings only to confirm a hypothesis.
- Always set `timeout` to `86400` on every `execute_python` call. The default is only 360 seconds. Never use a smaller value.
- Decompile with Hex-Rays instead of reading only disassembly. If the decompiler is unavailable for the architecture, say so.
- If the code is obfuscated or IDA can't read it (flattening, opaque predicates, junk code, anti-disassembly), deobfuscate it instead of giving up. Use only IDA Pro 9.5 itself (its APIs, Bochs debugger, and a small Python interpreter you write). Never pip install or import external packages.
- Never skip a function because it is large. Large functions are usually the most important: decompile them, reading long output in slices.
- Rename functions and variables, set types, and add comments as you learn, then re-decompile.
- Label claims `confirmed`, `likely`, or `guess`, and cite evidence.
- If an IDAPython call errors, check the `reference` tool and retry. Do not fall back to string search.

## Loading the skill

If the user asks to reverse, analyze, or decompile a binary, or says "load res" or "load res:res", and the `res` skill is not already loaded in this conversation, load it first, then follow it. A leading `quick` or `full` in the request is the mode. Do not ask whether to load it; just load it.

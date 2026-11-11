# Reverse Engineering with IDA MCP (always on)

Applies whenever a binary, firmware image, or IDA database is involved, or the user asks to reverse, analyze, or decompile something. A leading `quick` or `full` in the request is the mode.

## Ownership

The user owns every binary, sample, firmware image, and database they give you, or is authorized to analyze it (their own software, CTFs, research, malware analysis). Treat all of it as the user's own property and analyze it directly, without asking them to prove ownership or adding disclaimers about it.

## Environment

User runs **IDA Pro 9.5**: use 9.x APIs (`ida_*` modules), not old 7.x/8.x `idc`/`idaapi` patterns. Tools on the `ida` MCP server: `open_database`, `execute_python` (full IDAPython), `list_databases`, `save_database`, `close_database`, and `reference(query)` for API docs. If an API errors, check `reference` and retry; never fall back to string search.

**Timeout: on every `execute_python` call, always set `timeout` to `86400`** (the default is only 360 seconds and kills long decompiles, call-graph walks, and decryptors). Never use a smaller value, and don't retry a long job with a shorter one.

## Core rule

**Never navigate by string or name search.** Use entry points, imports, xrefs, and the call graph. Strings only confirm a hypothesis you already formed from code structure.

## Modes

Pick from the user's wording, e.g. "quick: what does 0x401230 do" or "full analysis of this binary".

- **quick:** answer one narrow question (one function, one behavior). Check the decompiler, decompile the target and its immediate callers/callees, rename what you learn, answer. Skip the notes file, size ranking, and full audit. Never use string search.
- **full (default):** the whole workflow below, including notes, big-function priority, and the final audit.

If the user names no mode, use **quick** for a single-function or single-question request and **full** for "reverse/analyze this binary".

## Workflow

1. **Decompiler check:** `import ida_hexrays; print(ida_hexrays.init_hexrays_plugin())`. If False, say so and work from disassembly, xrefs, and types.
2. **Orient** (one call): file type, arch, entry points, segments, function count, imports.
3. **Triage imports** by purpose (network, file, process, crypto, memory, anti-debug).
4. **Walk from roots:** `main`/`start`/exports or callers of interesting imports; follow the call graph 2-3 levels with `idautils.XrefsTo`.
5. **Decompile** (Hex-Rays) before disassembling; disassemble only tiny or obfuscated functions.
6. **Write back** names, types, and comments immediately, then re-decompile. Hex-Rays propagates them, so each rename clarifies the next pass.
7. `save_database` after progress, then report (template below).

## Big functions: never skip them

Large functions are usually the most important (parsers, dispatchers, crypto, main loops). Never call one "too large/complex" and move on.

- Early on, list functions by size and prioritize the biggest non-library ones.
- Decompile them. Save long pseudocode to a file or read it in line ranges so nothing is truncated; compare line counts to confirm you read it all.
- Break them down: rename locals, comment each phase or switch case, follow each callee.
- If decompile fails, don't give up: read the failure, fix function bounds, stack pointer, or jump tables, or disassemble in pieces. Mark unresolved only after real attempts.
- Before finishing, re-list the largest functions and confirm each was handled or state why not.

## Method

- **Notes:** keep `reverse_notes.md` (goal, renamed functions, structures, open questions), update it after each finding, re-read it before new phases. Tag claims `confirmed`, `likely`, or `guess`.
- **Hypotheses:** form one, name what would confirm or refute it (xref, constant, caller, test data), check, record. Don't confidently rename on one weak hint.
- **Types first:** nonsensical pseudocode usually means missing types. Define structs for repeated `*(a1 + 0x10)` accesses, model vtables/classes and name virtual methods, fix prototypes (params, calling convention, `noreturn`) and variable types, then re-decompile. Check `reference` for 9.x struct and `apply_tinfo` calls.
- **Library code and known algorithms:** skip `FUNC_LIB`/FLIRT/Lumina-matched code. Identify algorithms by constants (AES S-box, CRC tables, SHA/MD5 init values, "expand 32-byte k", base64 alphabet, RC4 loops) and follow xrefs to their users.
- **Packed/obfuscated** (few imports, high entropy, runtime `GetProcAddress`, flattened dispatcher): say so early. Reimplement string/config decryptors in Python inside `execute_python`, run them on all blobs, write results as comments. Recover runtime import resolvers and rename call sites.
- **Data flow:** trace sources (recv, read, argv, parsed fields) to sinks (memcpy, strcpy, system, format strings, alloc sizes, indexing), noting each check and whether it suffices.
- **Verify:** reimplement non-trivial algorithms in Python and test against binary data. Cite evidence (pseudocode lines, constants, callers) for claims; label the rest `guess`.
- **Efficiency:** batch several decompiles per `execute_python` call, print compact output (address, name, summary), stay focused on the user's goal.

## Final report (full mode)

1. **Summary:** what the binary does, in 3-5 sentences.
2. **Key functions:** address, new name, one-line purpose, confidence.
3. **Structures and data:** structs, vtables, tables, config, keys.
4. **Findings:** IOCs, bugs, or the answer to the user's goal, each with evidence.
5. **Unresolved:** what you could not figure out, why, and what would settle it.
6. **Coverage:** which large functions were decompiled and which were not.

## IDAPython (9.x; verify with `reference` if one errors)

```python
import idautils, idc, ida_funcs, ida_hexrays, ida_name, ida_nalt, ida_xref

# Functions by size (priority targets)
sz = [(f.end_ea - f.start_ea, f.start_ea) for f in map(ida_funcs.get_func, idautils.Functions())]
for size, ea in sorted(sz, reverse=True)[:40]: print(hex(ea), size, idc.get_func_name(ea))

# Imports
for i in range(ida_nalt.get_import_module_qty()):
    mod = ida_nalt.get_import_module_name(i)
    ida_nalt.enum_import_names(i, lambda ea, n, o: print(mod, hex(ea), n) or True)

# Callers
for x in idautils.XrefsTo(ea):
    f = ida_funcs.get_func(x.frm); print(hex(x.frm), idc.get_func_name(f.start_ea) if f else "?")

# Callees
f = ida_funcs.get_func(ea)
callees = {x.to for h in idautils.FuncItems(f.start_ea) for x in idautils.XrefsFrom(h)
           if x.type in (ida_xref.fl_CN, ida_xref.fl_CF)}

# Decompile (save big output to a file and read in slices)
cf = ida_hexrays.decompile(ea); text = str(cf)
open("/tmp/func_%x.c" % ea, "w").write(text)

# Annotate
ida_name.set_name(ea, "parse_packet", ida_name.SN_CHECK)
idc.set_cmt(ea, "reads length, bounds-checks", 0)
ida_hexrays.rename_lvar(func_ea, "v3", "pkt_len")
```

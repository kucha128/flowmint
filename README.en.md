# FlowMint

[中文](README.md) | **English**

A developer-focused **network-behavior analysis and development platform**: turn observed and
verified network traffic (**Flow**) into reusable, testable, deployable software network logic (**Mint**).

It ships a **desktop MITM analyzer** on par with Fiddler/Charles, a command-line tool, a
cross-runtime **Rule IR**, and **multi-language capture/rewrite SDKs** you can embed in your own apps.

Design north star (highest priority first): **easy to use → efficient to analyze → simple to ship into your own code**.

> ⚠️ **Authorized use & disclaimer**
> FlowMint is a man-in-the-middle (MITM) debugging tool that can decrypt and rewrite network traffic.
> It is intended **only for development, testing and security research on devices and traffic you own
> or are explicitly authorized to inspect**. You are responsible for complying with all applicable laws
> and terms of service. The authors and contributors accept **no liability** for misuse, unauthorized
> interception, or resulting damage (see [LICENSE](LICENSE)). FlowMint does **not** implement, and must
> not be used to, bypass certificate pinning, access control, or any system security mechanism.

> 📌 Project documentation under [`docs/`](docs/) is currently written in Chinese. This page is a summary
> for international readers; contributions of English docs are welcome.

---

## Highlights

- **Capture**: explicit HTTP/1.1 proxy + CONNECT tunnel + opt-in **HTTPS MITM** + WebSocket frame capture.
- **Inspect**: real-time session list (method / status / scheme / host / URL / type / size / process),
  multi-tab inspector, response-body **auto-decompression** (gzip/br/deflate/zstd), inline image preview.
- **Modify**: **breakpoints** (edit in-flight request/response), **replay / composer**, cURL export, HAR export.
- **Chain & integrate**: **upstream proxy chaining**, one-click system proxy, a built-in cert-download page
  with per-OS install guides, and a stable **C ABI** with thin bindings for
  C / C++ / C# / Go / Java / Python / E-language — including **intercept & rewrite** from your own code.
- **Rules & AI**: cross-runtime **Rule IR** with offline replay + structured diff, a read-only **MCP** server
  (redaction-enforced) and a local read-only REST API.

---

## Quick start

### Desktop app (recommended)

```powershell
cd apps\desktop
npm install
npm run tauri build -- --no-bundle
# run apps\desktop\src-tauri\target\release\flowmint-studio.exe
```

Click "▶ Start capture", point your client's HTTP proxy at `127.0.0.1:8888`, and traffic shows up live.

> **No preinstalled certificate needed.** The MITM CA is **generated locally on first use** (under
> `<exe-dir>/data/ca/`), unique per machine, with the private key kept only on your device. After you
> clone/download, just click "Install certificate" (or start MITM capture) to generate *your own* CA,
> then trust it locally. ⚠️ Never share or commit `data/ca/` (it holds the private key); ship only the
> executable in releases, never the `data/` directory.

### CLI (headless / CI / automation companion)

`flowmint.exe` targets **headless** scenarios the GUI and SDK don't cover: capturing on servers/CI,
validating & replaying rules in CI, and exposing captured data to AI/scripts over MCP/REST.

```powershell
cargo build --workspace
cargo run -p flowmint-cli -- --data mydata capture start --port 8888
# another terminal: curl.exe -x http://127.0.0.1:8888 http://target/
cargo run -p flowmint-cli -- --data mydata flow search
cargo run -p flowmint-cli -- --data mydata rule test --rule r.yaml --flow <flow_id>  # replay a rule in CI
cargo run -p flowmint-cli -- --data mydata mcp serve   # read-only MCP for AI clients
```

### SDK (intercept & rewrite)

Build the C ABI core (`cargo build -p flowmint-ffi --release` → `flowmint.dll`), then use a binding.
Runnable rewrite demos: [Python](sdks/python/demo_intercept.py), [C++](sdks/cpp/demo_intercept.cpp).

```python
import flowmint

def on_intercept(m: flowmint.Intercept) -> int:
    if m.is_response:
        m.set_status(200)
        m.set_body(b"REWRITTEN")
    else:
        m.set_header("X-FlowMint", "hello")
    return flowmint.MODIFY

flowmint.FlowMint().bind_port(8888).on_intercept(on_intercept).start()
```

---

## Layout

Rust workspace (multiple crates) + Tauri desktop app + multi-language SDKs.

| Component | Path | Role |
|---|---|---|
| Data contract | [crates/model](crates/model) | Event model, Flow, Rule IR, IDs, clock, errors |
| Storage | [crates/storage](crates/storage) | SQLite index + content-addressed chunk store |
| TLS/CA | [crates/tls](crates/tls) | Per-profile CA, on-demand leaf minting, rustls configs |
| Capture adapter | [crates/proxy-http](crates/proxy-http) | HTTP proxy + CONNECT + HTTPS MITM + WebSocket frames |
| Rule engine | [crates/rules](crates/rules) | Rule IR executor (match, actions, before/after diff) |
| Engine | [crates/engine](crates/engine) | Capture lifecycle, live broadcast, query/replay/export |
| REST API | [crates/api](crates/api) | Local read-only API (loopback + token) |
| MCP | [crates/mcp](crates/mcp) | Read-only AI tools + stdio server + redaction |
| C ABI core | [crates/ffi](crates/ffi) | Builds `flowmint` dynamic library for the SDK bindings |
| CLI | [apps/cli](apps/cli) | Command-line tool `flowmint` |
| Desktop | [apps/desktop](apps/desktop) | Tauri 2 analyzer (React front end + Rust back end) |
| SDKs | [sdks/](sdks/) | C/C++/C#/Go/Java/Python/E-language bindings over one C ABI |

---

## Scope & boundaries

- **Implemented**: HTTP capture, HTTPS MITM (with cert-download page & per-OS install), WebSocket frames,
  response decompression, full headers & body, breakpoints, replay/composer, upstream proxy chaining,
  one-click system proxy, per-process attribution, Rule IR + offline replay + diff, read-only MCP,
  local REST API, desktop analyzer, multi-language capture SDK (C ABI, incl. intercept & rewrite).
- **Not yet** (phased by design): TCP/UDP semantic rewrite, WS/TCP/UDP SDK callbacks, Wasm plugins,
  OS driver/TUN, HTTP/3, remote managed agent.
- **Security boundary**: binds loopback only by default; MITM off by default and requires explicit CA trust;
  undecrypted CONNECT tunnels record metadata only; AI/MCP is read-only and redaction-enforced.
  Use only on traffic you are authorized to inspect and modify.

## License

[MIT](LICENSE). Reused third-party components remain under their own licenses; maintain
`THIRD_PARTY_NOTICES` accordingly. Security policy: [SECURITY.md](SECURITY.md).

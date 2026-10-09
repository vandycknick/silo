import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import {
  NetworkForwardBuilder, NetworkForwardDefinitionBuilder, NetworkPolicy,
  type NetworkForwardProtocol, type NetworkForwardTLS,
} from "../../src/index.js";

// Loading is mandatory: an absent or stale addon must fail this suite, not skip it.
const require = createRequire(import.meta.url);
const addon: unknown = require("../../native/index.cjs");
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("expected an object");
  }
  return Object.fromEntries(Object.entries(value));
}
const exports = record(addon);
const native = exports.default === undefined ? exports : record(exports.default);
const build = native.buildNetworkPolicy;
if (typeof build !== "function") throw new TypeError("native buildNetworkPolicy is required");
function nativeBuild(input: unknown): unknown {
  return build(input);
}
function forwardOf(policy: NetworkPolicy): Record<string, unknown> {
  const document = record(JSON.parse(policy.toJson()));
  if (!Array.isArray(document.forwards)) throw new TypeError("expected forwards");
  return record(document.forwards[0]);
}

for (const style of ["definition", "fluent"] as const) {
  describe(`forward ${style} real addon`, () => {
    for (const protocol of [undefined, "tcp", "https"] as const) {
      it(`normalizes ${protocol ?? "implicit tcp"} without losing unbound tailscale`, () => {
        const configure = (forward: NetworkForwardBuilder | NetworkForwardDefinitionBuilder) => {
          forward.tailscale().target("self").targetPort(8080).listen(":00443");
          if (protocol !== undefined) forward.protocol(protocol);
          if (protocol === "https") forward.tls({ provider: "tailscale" });
        };
        const policy = style === "definition"
          ? NetworkPolicy.define((p) => configure(p.forward("web")))
          : NetworkPolicy.builder().forward("web", configure).build();
        expect(forwardOf(policy)).toMatchObject({
          kind: "tailscale", target: "self", target_port: 8080,
          listen: ":443", protocol: protocol ?? "tcp",
        });
        expect(forwardOf(policy).tunnel).toBeUndefined();
        if (protocol === "https") expect(forwardOf(policy).tls).toEqual({ provider: "tailscale" });
      });
    }

    it("preserves explicit declared tunnel binding", () => {
      const policy = style === "definition"
        ? NetworkPolicy.define((p) => {
          const tunnel = p.tailscale("vm");
          p.forward("web").tailscale().tunnel(tunnel).target("self").targetPort(8080).listen(":443");
        })
        : NetworkPolicy.builder().tailscale("vm", (t) => t)
          .forward("web", (f) => f.tailscale().tunnel("vm").target("self").targetPort(8080).listen(":443")).build();
      expect(forwardOf(policy).tunnel).toBe("vm");
    });

    it("does not erase incompatible HTTPS settings when host is selected", () => {
      const configure = (f: NetworkForwardBuilder | NetworkForwardDefinitionBuilder): void => {
        f.tailscale().protocol("https").tls({ provider: "tailscale" }).host()
          .target("name:web").targetPort(8080).listen("127.0.0.1:443");
      };
      expect(() => style === "definition"
        ? NetworkPolicy.define((p) => { configure(p.forward("web")); })
        : NetworkPolicy.builder().forward("web", configure).build()).toThrow();
    });
  });
}

describe("forward native validation", () => {
  const base = { name: "web", kind: "tailscale", target: "self", targetPort: 8080, listen: ":443" };
  it.each([
    { kind: "other" }, { protocol: "udp" }, { protocol: "https" },
    { tls: { provider: "tailscale" } }, { protocol: "https", tls: { provider: "other" } },
    { protocol: "https", tls: {} }, { targetPort: 0 }, { targetPort: 65536 },
    { protocol: "https", tls: { provider: "tailscale", domain: "evil.example" } },
    { listen: ":22" }, { listen: ":0" }, { listen: ":65536" },
    { listen: "0.0.0.0:443" }, { listen: ":+443" }, { tunnel: "missing" },
    { kind: "host" }, { protocol: "https", tls: { provider: "tailscale" }, target: "name:web" },
  ])("rejects invalid explicit input %j", (change) => {
    expect(() => nativeBuild({ forwards: [{ ...base, ...change }] })).toThrow();
  });
  it("rejects duplicate normalized listener ports", () => {
    expect(() => nativeBuild({ forwards: [base, { ...base, name: "duplicate", listen: ":00443" }] })).toThrow();
  });
  it("retains omitted-kind tunnel inference", () => {
    const output = nativeBuild({ tailscale: [{ name: "vm" }], forwards: [{
      name: "web", tunnel: "vm", target: "self", targetPort: 8080, listen: ":443",
    }] });
    if (typeof output !== "string") throw new TypeError("expected canonical JSON");
    expect(record(JSON.parse(output)).forwards).toEqual([{
      name: "web", kind: "tailscale", tunnel: "vm", target: "self",
      target_port: 8080, listen: ":443", protocol: "tcp",
    }]);
  });
});

describe("forward nested TLS ownership", () => {
  it.each([NetworkForwardBuilder, NetworkForwardDefinitionBuilder])("copies TLS on input and output", (Builder) => {
    const tls: NetworkForwardTLS = { provider: "tailscale" };
    const protocol: NetworkForwardProtocol = "https";
    const builder = new Builder("web").tailscale().target("self").targetPort(8080)
      .listen(":443").protocol(protocol).tls(tls);
    Object.defineProperty(tls, "provider", { value: "other" });
    const first = builder.toNative();
    if (first.tls !== undefined) Object.defineProperty(first.tls, "provider", { value: "other" });
    const output = nativeBuild({ forwards: [builder.toNative()] });
    if (typeof output !== "string") throw new TypeError("expected canonical JSON");
    expect(record(JSON.parse(output)).forwards).toEqual([{
      name: "web", kind: "tailscale", target: "self", target_port: 8080,
      listen: ":443", protocol: "https", tls: { provider: "tailscale" },
    }]);
  });
});

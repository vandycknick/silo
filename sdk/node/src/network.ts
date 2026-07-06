import { createRequire } from "node:module";
import type { NativeNetworkAuditInput, NativeNetworkCredentialInput, NativeNetworkEndpointInput, NativeNetworkForwardInput, NativeNetworkInput, NativeNetworkPolicyInput, NativeNetworkRuleInput, NativeTailscaleTunnelInput } from "./internal/napi.js";
import {
  assertBoolean,
  assertI32,
  assertNonEmptyString,
  assertNonEmptyStringArray,
  assertNonNegativeInteger,
  assertPositiveU16,
  assertString,
} from "./validation.js";

const require = createRequire(import.meta.url);
const nativeAddonPath = "../native/index.cjs";

type BuilderCallback<T> = (builder: T) => T | void;
export type NetworkPolicyDefinitionCallback = (policy: NetworkPolicyDefinition) => void;

function applyBuilder<T>(builder: T, configure: BuilderCallback<T>): T {
  return configure(builder) ?? builder;
}

/** Canonical network policy JSON produced by Bento's Rust policy builder. */
export class NetworkPolicy {
  private constructor(private readonly policyJson: string) {}

  /** Build a canonical policy through the typed definition API. */
  static define(configure: NetworkPolicyDefinitionCallback): NetworkPolicy {
    const definition = new NetworkPolicyDefinition();
    configure(definition);
    return definition.build();
  }

  /** Start a fluent policy builder. */
  static builder(): NetworkPolicyBuilder {
    return new NetworkPolicyBuilder();
  }

  /** Wrap existing canonical network policy JSON. */
  static fromJson(json: string): NetworkPolicy {
    return new NetworkPolicy(assertNonEmptyString(json, "json"));
  }

  /** Return canonical network policy JSON. */
  toJson(): string {
    return this.policyJson;
  }

  toString(): string {
    return this.policyJson;
  }
}

/** Fluent builder for canonical network policies. */
export class NetworkPolicyBuilder {
  private readonly input: NativeNetworkPolicyInput = {};

  defaultAllow(): this {
    this.input.defaultAction = "allow";
    return this;
  }

  defaultDeny(): this {
    this.input.defaultAction = "deny";
    return this;
  }

  metadata(key: string, value: string): this {
    const metadata = this.input.metadata ?? [];
    metadata.push({
      key: assertNonEmptyString(key, "key"),
      value: assertString(value, "value"),
    });
    this.input.metadata = metadata;
    return this;
  }

  audit(configure: BuilderCallback<NetworkAuditBuilder>): this {
    this.input.audit = applyBuilder(new NetworkAuditBuilder(), configure).toNative();
    return this;
  }

  endpoint(name: string, configure: BuilderCallback<NetworkEndpointBuilder>): this {
    const endpoints = this.input.endpoints ?? [];
    endpoints.push(
      applyBuilder(new NetworkEndpointBuilder(name), configure).toNative(),
    );
    this.input.endpoints = endpoints;
    return this;
  }

  credential(name: string, configure: BuilderCallback<NetworkCredentialBuilder>): this {
    const credentials = this.input.credentials ?? [];
    credentials.push(
      applyBuilder(new NetworkCredentialBuilder(name), configure).toNative(),
    );
    this.input.credentials = credentials;
    return this;
  }

  rule(name: string, configure: BuilderCallback<NetworkRuleBuilder>): this {
    const rules = this.input.rules ?? [];
    rules.push(
      applyBuilder(new NetworkRuleBuilder(assertNonEmptyString(name, "name")), configure).toNative(),
    );
    this.input.rules = rules;
    return this;
  }

  unnamedRule(configure: BuilderCallback<NetworkRuleBuilder>): this {
    const rules = this.input.rules ?? [];
    rules.push(applyBuilder(new NetworkRuleBuilder(), configure).toNative());
    this.input.rules = rules;
    return this;
  }

  tailscale(name: string, configure: BuilderCallback<TailscaleTunnelBuilder>): this {
    const tailscale = this.input.tailscale ?? [];
    tailscale.push(
      applyBuilder(new TailscaleTunnelBuilder(name), configure).toNative(),
    );
    this.input.tailscale = tailscale;
    return this;
  }

  forward(name: string, configure: BuilderCallback<NetworkForwardBuilder>): this {
    const forwards = this.input.forwards ?? [];
    forwards.push(
      applyBuilder(new NetworkForwardBuilder(name), configure).toNative(),
    );
    this.input.forwards = forwards;
    return this;
  }

  build(): NetworkPolicy {
    return NetworkPolicy.fromJson(buildNetworkPolicy(this.input));
  }
}

/** Typed, reference-based policy definition API. */
export class NetworkPolicyDefinition {
  private readonly input: NativeNetworkPolicyInput = {};
  private readonly endpoints: NetworkEndpointRef[] = [];
  private readonly credentials: NetworkCredentialRef[] = [];
  private readonly rules: NetworkRuleDefinitionBuilder[] = [];
  private readonly tailscaleTunnels: TailscaleTunnelRef[] = [];
  private readonly forwards: NetworkForwardDefinitionBuilder[] = [];

  defaultAllow(): this {
    this.input.defaultAction = "allow";
    return this;
  }

  defaultDeny(): this {
    this.input.defaultAction = "deny";
    return this;
  }

  metadata(key: string, value: string): this {
    const metadata = this.input.metadata ?? [];
    metadata.push({
      key: assertNonEmptyString(key, "key"),
      value: assertString(value, "value"),
    });
    this.input.metadata = metadata;
    return this;
  }

  audit(configure: BuilderCallback<NetworkAuditBuilder>): this {
    this.input.audit = applyBuilder(new NetworkAuditBuilder(), configure).toNative();
    return this;
  }

  endpoint(name: string): NetworkEndpointSelector {
    return new NetworkEndpointSelectorImpl(name, (endpoint) => {
      this.endpoints.push(endpoint);
    });
  }

  credential(name: string): NetworkCredentialDefinitionBuilder {
    const credential = new NetworkCredentialDefinitionBuilder(name);
    this.credentials.push(credential);
    return credential;
  }

  rule(name: string): NetworkRuleDefinitionBuilder {
    const rule = new NetworkRuleDefinitionBuilder(assertNonEmptyString(name, "name"));
    this.rules.push(rule);
    return rule;
  }

  unnamedRule(): NetworkRuleDefinitionBuilder {
    const rule = new NetworkRuleDefinitionBuilder();
    this.rules.push(rule);
    return rule;
  }

  tailscale(name: string): TailscaleTunnelBuilder {
    const tunnel = new TailscaleTunnelBuilder(name);
    this.tailscaleTunnels.push(tunnel);
    return tunnel;
  }

  forward(name: string): NetworkForwardDefinitionBuilder {
    const forward = new NetworkForwardDefinitionBuilder(name);
    this.forwards.push(forward);
    return forward;
  }

  build(): NetworkPolicy {
    const input: NativeNetworkPolicyInput = { ...this.input };
    if (this.endpoints.length > 0) {
      input.endpoints = this.endpoints.map((endpoint) => endpoint.toNative());
    }
    if (this.credentials.length > 0) {
      input.credentials = this.credentials.map((credential) => credential.toNative());
    }
    if (this.rules.length > 0) {
      input.rules = this.rules.map((rule) => rule.toNative());
    }
    if (this.tailscaleTunnels.length > 0) {
      input.tailscale = this.tailscaleTunnels.map((tunnel) => tunnel.toNative());
    }
    if (this.forwards.length > 0) {
      input.forwards = this.forwards.map((forward) => forward.toNative());
    }
    return NetworkPolicy.fromJson(buildNetworkPolicy(input));
  }
}

type EndpointRegistration = (endpoint: NetworkEndpointRef) => void;

export abstract class NetworkEndpointRef {
  readonly #endpointRefBrand = true;

  abstract get name(): string;
  abstract toNative(): NativeNetworkEndpointInput;
}

export abstract class NetworkCredentialRef {
  readonly #credentialRefBrand = true;

  abstract get name(): string;
  abstract toNative(): NativeNetworkCredentialInput;
}

export abstract class TailscaleTunnelRef {
  readonly #tailscaleTunnelRefBrand = true;

  abstract get name(): string;
  abstract toNative(): NativeTailscaleTunnelInput;
}

class NetworkEndpointState {
  private registered = false;
  readonly input: NativeNetworkEndpointInput;

  constructor(
    name: string,
    kind: "ip" | "http" | "https",
    private readonly registerEndpoint: EndpointRegistration,
  ) {
    this.input = { name: assertNonEmptyString(name, "name"), kind };
  }

  register(endpoint: NetworkEndpointRef): void {
    if (this.registered) return;
    this.registerEndpoint(endpoint);
    this.registered = true;
  }
}

abstract class NetworkEndpointRefBase extends NetworkEndpointRef {
  protected constructor(protected readonly state: NetworkEndpointState) {
    super();
  }

  get name(): string {
    return this.state.input.name;
  }

  toNative(): NativeNetworkEndpointInput {
    return cloneEndpointInput(this.state.input);
  }
}

export interface NetworkEndpointSelector {
  ip(): IpEndpointBuilder;
  http(): HttpEndpointBuilder;
  https(): HttpsEndpointBuilder;
}

export interface IpEndpointBuilder extends NetworkEndpointRef {
  fromCidr(cidr: string): this;
  toCidr(cidr: string): this;
  sourceCidr(cidr: string): this;
  destinationCidr(cidr: string): this;
  tcp(): IpProtocolEndpointBuilder;
  udp(): IpProtocolEndpointBuilder;
}

export interface IpProtocolEndpointBuilder extends NetworkEndpointRef {
  fromCidr(cidr: string): this;
  toCidr(cidr: string): this;
  sourceCidr(cidr: string): this;
  destinationCidr(cidr: string): this;
  tcp(): this;
  udp(): this;
  port(port: number): this;
  portRange(start: number, end: number): this;
}

export interface HttpEndpointBuilder {
  host(host: string): HttpEndpointRef;
}

export interface HttpsEndpointBuilder {
  host(host: string): HttpsEndpointRef;
}

export interface HttpEndpointRef extends NetworkEndpointRef {
  host(host: string): this;
}

export interface HttpsEndpointRef extends NetworkEndpointRef {
  host(host: string): this;
}

class NetworkEndpointSelectorImpl implements NetworkEndpointSelector {
  constructor(
    private readonly name: string,
    private readonly registerEndpoint: EndpointRegistration,
  ) {}

  ip(): IpEndpointBuilder {
    const state = new NetworkEndpointState(this.name, "ip", this.registerEndpoint);
    const endpoint = new IpEndpointBuilderImpl(state);
    state.register(endpoint);
    return endpoint;
  }

  http(): HttpEndpointBuilder {
    return new HttpEndpointBuilderImpl(
      new NetworkEndpointState(this.name, "http", this.registerEndpoint),
    );
  }

  https(): HttpsEndpointBuilder {
    return new HttpsEndpointBuilderImpl(
      new NetworkEndpointState(this.name, "https", this.registerEndpoint),
    );
  }
}

class IpEndpointBuilderImpl extends NetworkEndpointRefBase implements IpEndpointBuilder {
  constructor(state: NetworkEndpointState) {
    super(state);
  }

  fromCidr(cidr: string): this {
    const sourceCidrs = this.state.input.sourceCidrs ?? [];
    sourceCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.state.input.sourceCidrs = sourceCidrs;
    return this;
  }

  toCidr(cidr: string): this {
    const destinationCidrs = this.state.input.destinationCidrs ?? [];
    destinationCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.state.input.destinationCidrs = destinationCidrs;
    return this;
  }

  sourceCidr(cidr: string): this {
    return this.fromCidr(cidr);
  }

  destinationCidr(cidr: string): this {
    return this.toCidr(cidr);
  }

  tcp(): IpProtocolEndpointBuilder {
    this.state.input.protocol = "tcp";
    return new IpProtocolEndpointBuilderImpl(this.state);
  }

  udp(): IpProtocolEndpointBuilder {
    this.state.input.protocol = "udp";
    return new IpProtocolEndpointBuilderImpl(this.state);
  }
}

class IpProtocolEndpointBuilderImpl
  extends NetworkEndpointRefBase
  implements IpProtocolEndpointBuilder
{
  constructor(state: NetworkEndpointState) {
    super(state);
  }

  fromCidr(cidr: string): this {
    const sourceCidrs = this.state.input.sourceCidrs ?? [];
    sourceCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.state.input.sourceCidrs = sourceCidrs;
    return this;
  }

  toCidr(cidr: string): this {
    const destinationCidrs = this.state.input.destinationCidrs ?? [];
    destinationCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.state.input.destinationCidrs = destinationCidrs;
    return this;
  }

  sourceCidr(cidr: string): this {
    return this.fromCidr(cidr);
  }

  destinationCidr(cidr: string): this {
    return this.toCidr(cidr);
  }

  tcp(): this {
    this.state.input.protocol = "tcp";
    return this;
  }

  udp(): this {
    this.state.input.protocol = "udp";
    return this;
  }

  port(port: number): this {
    const ports = this.state.input.ports ?? [];
    ports.push({ start: assertPositiveU16(port, "port") });
    this.state.input.ports = ports;
    return this;
  }

  portRange(start: number, end: number): this {
    const ports = this.state.input.ports ?? [];
    ports.push({
      start: assertPositiveU16(start, "start"),
      end: assertPositiveU16(end, "end"),
    });
    this.state.input.ports = ports;
    return this;
  }
}

class HttpEndpointBuilderImpl implements HttpEndpointBuilder {
  private endpoint?: HttpEndpointRefImpl;

  constructor(private readonly state: NetworkEndpointState) {}

  host(host: string): HttpEndpointRef {
    const endpoint = this.endpoint ?? new HttpEndpointRefImpl(this.state);
    this.endpoint = endpoint;
    endpoint.host(host);
    this.state.register(endpoint);
    return endpoint;
  }
}

class HttpsEndpointBuilderImpl implements HttpsEndpointBuilder {
  private endpoint?: HttpsEndpointRefImpl;

  constructor(private readonly state: NetworkEndpointState) {}

  host(host: string): HttpsEndpointRef {
    const endpoint = this.endpoint ?? new HttpsEndpointRefImpl(this.state);
    this.endpoint = endpoint;
    endpoint.host(host);
    this.state.register(endpoint);
    return endpoint;
  }
}

class HttpEndpointRefImpl extends NetworkEndpointRefBase implements HttpEndpointRef {
  constructor(state: NetworkEndpointState) {
    super(state);
  }

  host(host: string): this {
    const hosts = this.state.input.hosts ?? [];
    hosts.push(assertNonEmptyString(host, "host"));
    this.state.input.hosts = hosts;
    return this;
  }
}

class HttpsEndpointRefImpl extends NetworkEndpointRefBase implements HttpsEndpointRef {
  constructor(state: NetworkEndpointState) {
    super(state);
  }

  host(host: string): this {
    const hosts = this.state.input.hosts ?? [];
    hosts.push(assertNonEmptyString(host, "host"));
    this.state.input.hosts = hosts;
    return this;
  }
}

export class NetworkCredentialDefinitionBuilder extends NetworkCredentialRef {
  private readonly input: NativeNetworkCredentialInput;

  constructor(name: string) {
    super();
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  get name(): string {
    return this.input.name;
  }

  basicAuth(): this {
    this.input.kind = "basic_auth";
    return this;
  }

  bearerToken(): this {
    this.input.kind = "bearer_token";
    return this;
  }

  headerToken(): this {
    this.input.kind = "header_token";
    return this;
  }

  githubOauth(): this {
    this.input.kind = "github_oauth";
    return this;
  }

  openaiCodexOauth(): this {
    this.input.kind = "openai_codex_oauth";
    return this;
  }

  awsCredential(): this {
    this.input.kind = "aws_credential";
    return this;
  }

  endpoint(endpoint: NetworkEndpointRef): this {
    this.input.endpoint = endpoint.name;
    return this;
  }

  username(username: string): this {
    this.input.username = assertNonEmptyString(username, "username");
    return this;
  }

  header(header: string): this {
    this.input.header = assertNonEmptyString(header, "header");
    return this;
  }

  prefix(prefix: string): this {
    this.input.prefix = assertString(prefix, "prefix");
    return this;
  }

  idempotencyKey(): this {
    this.input.idempotencyKey = true;
    return this;
  }

  idempotencyKeyEnabled(enabled: boolean): this {
    this.input.idempotencyKey = assertBoolean(enabled, "enabled");
    return this;
  }

  condition(condition: string): this {
    this.input.condition = assertNonEmptyString(condition, "condition");
    return this;
  }

  toNative(): NativeNetworkCredentialInput {
    return { ...this.input };
  }
}

export class NetworkRuleDefinitionBuilder {
  private readonly input: NativeNetworkRuleInput;

  constructor(name?: string) {
    this.input = name === undefined ? {} : { name };
  }

  endpoint(endpoint: NetworkEndpointRef): this {
    const endpoints = this.input.endpoints ?? [];
    endpoints.push(endpoint.name);
    this.input.endpoints = endpoints;
    return this;
  }

  credential(credential: NetworkCredentialRef): this {
    this.input.credential = credential.name;
    return this;
  }

  condition(condition: string): this {
    this.input.condition = assertNonEmptyString(condition, "condition");
    return this;
  }

  tunnel(tunnel: TailscaleTunnelRef): this {
    this.input.tunnel = tunnel.name;
    return this;
  }

  priority(priority: number): this {
    this.input.priority = assertI32(priority, "priority");
    return this;
  }

  disabled(disabled = true): this {
    this.input.disabled = assertBoolean(disabled, "disabled");
    return this;
  }

  reason(reason: string): this {
    this.input.reason = assertString(reason, "reason");
    return this;
  }

  allow(): this {
    this.input.verdict = "allow";
    return this;
  }

  deny(): this {
    this.input.verdict = "deny";
    return this;
  }

  toNative(): NativeNetworkRuleInput {
    return {
      ...this.input,
      endpoints: this.input.endpoints?.slice(),
    };
  }
}

export class NetworkForwardDefinitionBuilder {
  private readonly input: NativeNetworkForwardInput;

  constructor(name: string) {
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  host(): this {
    this.input.kind = "host";
    this.input.tunnel = undefined;
    return this;
  }

  tailscale(tunnel: TailscaleTunnelRef): this {
    this.input.kind = "tailscale";
    this.input.tunnel = tunnel.name;
    return this;
  }

  target(target: string): this {
    this.input.target = assertNonEmptyString(target, "target");
    return this;
  }

  targetPort(port: number): this {
    this.input.targetPort = assertPositiveU16(port, "port");
    return this;
  }

  listen(listen: string): this {
    this.input.listen = assertNonEmptyString(listen, "listen");
    return this;
  }

  toNative(): NativeNetworkForwardInput {
    return { ...this.input };
  }
}

export class NetworkAuditBuilder {
  private readonly input: NativeNetworkAuditInput = {};

  bodyBufferBytes(bytes: number): this {
    this.input.bodyBufferBytes = assertNonNegativeInteger(bytes, "bytes");
    return this;
  }

  bodyStorageBytes(bytes: number): this {
    this.input.bodyStorageBytes = assertNonNegativeInteger(bytes, "bytes");
    return this;
  }

  toNative(): NativeNetworkAuditInput {
    return { ...this.input };
  }
}

export class NetworkEndpointBuilder {
  private readonly input: NativeNetworkEndpointInput;

  constructor(name: string) {
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  ip(): this {
    this.input.kind = "ip";
    return this;
  }

  http(): this {
    this.input.kind = "http";
    return this;
  }

  https(): this {
    this.input.kind = "https";
    return this;
  }

  sourceCidr(cidr: string): this {
    const sourceCidrs = this.input.sourceCidrs ?? [];
    sourceCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.input.sourceCidrs = sourceCidrs;
    return this;
  }

  destinationCidr(cidr: string): this {
    const destinationCidrs = this.input.destinationCidrs ?? [];
    destinationCidrs.push(assertNonEmptyString(cidr, "cidr"));
    this.input.destinationCidrs = destinationCidrs;
    return this;
  }

  anyProtocol(): this {
    this.input.protocol = "any";
    return this;
  }

  tcp(): this {
    this.input.protocol = "tcp";
    return this;
  }

  udp(): this {
    this.input.protocol = "udp";
    return this;
  }

  port(port: number): this {
    const ports = this.input.ports ?? [];
    ports.push({ start: assertPositiveU16(port, "port") });
    this.input.ports = ports;
    return this;
  }

  portRange(start: number, end: number): this {
    const ports = this.input.ports ?? [];
    ports.push({
      start: assertPositiveU16(start, "start"),
      end: assertPositiveU16(end, "end"),
    });
    this.input.ports = ports;
    return this;
  }

  host(host: string): this {
    const hosts = this.input.hosts ?? [];
    hosts.push(assertNonEmptyString(host, "host"));
    this.input.hosts = hosts;
    return this;
  }

  toNative(): NativeNetworkEndpointInput {
    return { ...this.input };
  }
}

export class NetworkCredentialBuilder {
  private readonly input: NativeNetworkCredentialInput;

  constructor(name: string) {
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  basicAuth(): this {
    this.input.kind = "basic_auth";
    return this;
  }

  bearerToken(): this {
    this.input.kind = "bearer_token";
    return this;
  }

  headerToken(): this {
    this.input.kind = "header_token";
    return this;
  }

  githubOauth(): this {
    this.input.kind = "github_oauth";
    return this;
  }

  openaiCodexOauth(): this {
    this.input.kind = "openai_codex_oauth";
    return this;
  }

  awsCredential(): this {
    this.input.kind = "aws_credential";
    return this;
  }

  endpoint(endpoint: string): this {
    this.input.endpoint = assertNonEmptyString(endpoint, "endpoint");
    return this;
  }

  username(username: string): this {
    this.input.username = assertNonEmptyString(username, "username");
    return this;
  }

  header(header: string): this {
    this.input.header = assertNonEmptyString(header, "header");
    return this;
  }

  prefix(prefix: string): this {
    this.input.prefix = assertString(prefix, "prefix");
    return this;
  }

  idempotencyKey(): this {
    this.input.idempotencyKey = true;
    return this;
  }

  idempotencyKeyEnabled(enabled: boolean): this {
    this.input.idempotencyKey = assertBoolean(enabled, "enabled");
    return this;
  }

  condition(condition: string): this {
    this.input.condition = assertNonEmptyString(condition, "condition");
    return this;
  }

  toNative(): NativeNetworkCredentialInput {
    return { ...this.input };
  }
}

export class NetworkRuleBuilder {
  private readonly input: NativeNetworkRuleInput;

  constructor(name?: string) {
    this.input = name === undefined ? {} : { name };
  }

  endpoint(endpoint: string): this {
    const endpoints = this.input.endpoints ?? [];
    endpoints.push(assertNonEmptyString(endpoint, "endpoint"));
    this.input.endpoints = endpoints;
    return this;
  }

  credential(credential: string): this {
    this.input.credential = assertNonEmptyString(credential, "credential");
    return this;
  }

  condition(condition: string): this {
    this.input.condition = assertNonEmptyString(condition, "condition");
    return this;
  }

  tunnel(tunnel: string): this {
    this.input.tunnel = assertNonEmptyString(tunnel, "tunnel");
    return this;
  }

  priority(priority: number): this {
    this.input.priority = assertI32(priority, "priority");
    return this;
  }

  disabled(disabled: boolean): this {
    this.input.disabled = assertBoolean(disabled, "disabled");
    return this;
  }

  reason(reason: string): this {
    this.input.reason = assertString(reason, "reason");
    return this;
  }

  allow(): this {
    this.input.verdict = "allow";
    return this;
  }

  deny(): this {
    this.input.verdict = "deny";
    return this;
  }

  toNative(): NativeNetworkRuleInput {
    return { ...this.input };
  }
}

export class TailscaleTunnelBuilder extends TailscaleTunnelRef {
  private readonly input: NativeTailscaleTunnelInput;

  constructor(name: string) {
    super();
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  get name(): string {
    return this.input.name;
  }

  tag(tag: string): this {
    const tags = this.input.tags ?? [];
    tags.push(assertNonEmptyString(tag, "tag"));
    this.input.tags = tags;
    return this;
  }

  tags(tags: string[]): this {
    this.input.tags = assertNonEmptyStringArray(tags, "tags");
    return this;
  }

  hostname(hostname: string): this {
    this.input.hostname = assertNonEmptyString(hostname, "hostname");
    return this;
  }

  controlUrl(controlUrl: string): this {
    this.input.controlUrl = assertNonEmptyString(controlUrl, "controlUrl");
    return this;
  }

  toNative(): NativeTailscaleTunnelInput {
    return {
      ...this.input,
      tags: this.input.tags?.slice(),
    };
  }
}

export class NetworkForwardBuilder {
  private readonly input: NativeNetworkForwardInput;

  constructor(name: string) {
    this.input = { name: assertNonEmptyString(name, "name") };
  }

  host(): this {
    this.input.kind = "host";
    this.input.tunnel = undefined;
    return this;
  }

  tailscale(tunnel: string): this {
    this.input.kind = "tailscale";
    this.input.tunnel = assertNonEmptyString(tunnel, "tunnel");
    return this;
  }

  target(target: string): this {
    this.input.target = assertNonEmptyString(target, "target");
    return this;
  }

  targetPort(port: number): this {
    this.input.targetPort = assertPositiveU16(port, "port");
    return this;
  }

  listen(listen: string): this {
    this.input.listen = assertNonEmptyString(listen, "listen");
    return this;
  }

  toNative(): NativeNetworkForwardInput {
    return { ...this.input };
  }
}

/** Fluent builder for a machine's durable network attachment. */
export class MachineNetworkBuilder {
  private input: NativeNetworkInput = { kind: "private" };

  private(): this {
    this.input = { kind: "private" };
    return this;
  }

  none(): this {
    this.input = { kind: "none" };
    return this;
  }

  named(name: string): this {
    this.input = { kind: "named", name: assertNonEmptyString(name, "name") };
    return this;
  }

  policy(policy: NetworkPolicy): this {
    if (!(policy instanceof NetworkPolicy)) {
      throw new TypeError("policy must be a NetworkPolicy");
    }
    this.input = { ...this.input, policyJson: policy.toJson() };
    return this;
  }

  toNative(): NativeNetworkInput {
    return { ...this.input };
  }
}

export type MachineNetworkBuilderCallback = BuilderCallback<MachineNetworkBuilder>;

function cloneEndpointInput(input: NativeNetworkEndpointInput): NativeNetworkEndpointInput {
  return {
    ...input,
    sourceCidrs: input.sourceCidrs?.slice(),
    destinationCidrs: input.destinationCidrs?.slice(),
    ports: input.ports?.map((port) => ({ ...port })),
    hosts: input.hosts?.slice(),
  };
}

function buildNetworkPolicy(input: NativeNetworkPolicyInput): string {
  const loaded: unknown = require(nativeAddonPath);
  const loadedRecord = plainRecord(loaded, "native module");
  const exported = loadedRecord.default ?? loadedRecord;
  const native = plainRecord(exported, "native exports");
  const build = native.buildNetworkPolicy;
  if (!isNetworkPolicyBuilder(build)) {
    throw new TypeError("native addon does not export buildNetworkPolicy");
  }
  return build(input);
}

function plainRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function isNetworkPolicyBuilder(
  value: unknown,
): value is (input: NativeNetworkPolicyInput) => string {
  return typeof value === "function";
}

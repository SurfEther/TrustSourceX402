declare module 'whois-json' {
  // Options are forwarded to the underlying `whois` package. We set
  // `follow: 0` to disable referral-chasing (an SSRF vector — the referral
  // host:port is attacker-influenced and dialed with no private-IP guard) and
  // an explicit short `timeout` to bound socket lifetime.
  interface WhoisOptions {
    follow?: number;
    timeout?: number;
    server?: string;
    verbose?: boolean;
  }
  function whois(domain: string, options?: WhoisOptions): Promise<Record<string, string>>;
  export default whois;
}

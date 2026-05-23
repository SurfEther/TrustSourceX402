declare module 'whois-json' {
  function whois(domain: string): Promise<Record<string, string>>;
  export default whois;
}

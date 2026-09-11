export class JargonFilter {
  private static readonly CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;
  private static readonly NIST_CONTROL_REGEX = /\b(?:NIST[-\s]800-53\s+)?(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PS|RA|SA|SC|SI|SR)-\d+(?:\.\d+)?\b/gi;
  private static readonly PCI_CONTROL_REGEX = /\bPCI(?:-DSS)?(?:\s+v?\d+)?(?:\s+Req(?:uirement)?)?\s+\d+\.\d+(?:\.\d+)?\b/gi;
  private static readonly SOC2_CONTROL_REGEX = /\b(?:SOC\s*2\s+)?CC\d+\.\d+\b/gi;
  private static readonly IAM_ACTION_REGEX = /\b[a-z0-9-]+:[A-Za-z0-9*]+\b/g;
  private static readonly FILE_PATH_REGEX = /\b(?:[a-zA-Z]:[\\/]|[\w.-]+[\\/])+[\w.-]+\.(?:ts|js|tf|yaml|json|xml|py|java|go)\b/gi;

  public static sanitize(text: string): string {
    return text
      .replace(this.CVE_REGEX, 'known security vulnerability')
      .replace(this.NIST_CONTROL_REGEX, 'standard security control')
      .replace(this.PCI_CONTROL_REGEX, 'payment compliance control')
      .replace(this.SOC2_CONTROL_REGEX, 'audit control requirement')
      .replace(this.IAM_ACTION_REGEX, 'access permission grant')
      .replace(this.FILE_PATH_REGEX, 'system configuration file');
  }

  public static containsJargon(text: string): boolean {
    return (
      this.CVE_REGEX.test(text) ||
      this.NIST_CONTROL_REGEX.test(text) ||
      this.PCI_CONTROL_REGEX.test(text) ||
      this.SOC2_CONTROL_REGEX.test(text) ||
      this.IAM_ACTION_REGEX.test(text) ||
      this.FILE_PATH_REGEX.test(text)
    );
  }
}

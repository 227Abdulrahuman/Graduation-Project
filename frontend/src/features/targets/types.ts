
export type Target = {
  id: string;
  name: string;
  type: string;
  platform: "Bugcrowd" | "Hackerone" | "YesWeHack" | "Intigriti" | "Synack" | "External";
  program_url: string;
  domains: string[];
}
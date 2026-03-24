import { Globe, Bug, Lock } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  target: string;
  type: string;
  age: string;
}

export default function VulnerabilitiesTable({
  vulnerabilities,
}: {
  vulnerabilities: Vulnerability[];
}) {
  return (
    <Card className="overflow-hidden">
      <table className="w-full text-left">
        <thead>
          <tr className="bg-zinc-900/50 text-[10px] font-bold text-zinc-500 uppercase tracking-widest border-b border-zinc-800">
            <th className="px-6 py-4">ID</th>
            <th className="px-6 py-4">Vulnerability</th>
            <th className="px-6 py-4">Target</th>
            <th className="px-6 py-4">Severity</th>
            <th className="px-6 py-4">Type</th>
            <th className="px-6 py-4 text-right">Age</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {vulnerabilities.length === 0 ? (
            <tr>
              <td colSpan={6} className="px-6 py-8 text-center text-zinc-500">
                No vulnerabilities found matching those filters.
              </td>
            </tr>
          ) : (
            vulnerabilities.map((v) => (
              <tr
                key={v.id}
                className="group hover:bg-zinc-800/30 transition-colors cursor-pointer"
              >
                <td className="px-6 py-4 text-xs font-mono text-zinc-500">
                  {v.id}
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        "p-1.5 rounded bg-zinc-800",
                        v.severity === "Critical"
                          ? "text-red-500"
                          : v.severity === "High"
                            ? "text-orange-500"
                            : v.severity === "Medium"
                              ? "text-amber-500"
                              : "text-blue-500",
                      )}
                    >
                      {v.type === "DNS" ? (
                        <Globe className="w-3.5 h-3.5" />
                      ) : v.type === "Web" ? (
                        <Bug className="w-3.5 h-3.5" />
                      ) : (
                        <Lock className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <span className="font-bold text-zinc-200 group-hover:text-emerald-400 transition-colors">
                        {v.title}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-zinc-400 font-mono">
                  {v.target}
                </td>
                <td className="px-6 py-4">
                  <Badge
                    variant={
                      (v.severity === "Critical" || v.severity === "High"
                        ? "error"
                        : v.severity === "Medium"
                          ? "warning"
                          : "info") as "error" | "warning" | "info"
                    }
                  >
                    {v.severity}
                  </Badge>
                </td>
                <td className="px-6 py-4 text-xs text-zinc-500">{v.type}</td>
                <td className="px-6 py-4 text-right text-xs text-zinc-500">
                  {v.age}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </Card>
  );
}

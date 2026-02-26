import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import { MoreVertical } from "lucide-react";

const recentScans = [
  {
    id: "SCAN-001",
    target: "https://example.com",
    type: "Reconnaissance",
    progress: 100,
    status: "Completed",
    time: "2 min ago",
  },
  {
    id: "SCAN-002",
    target: "https://api.example.com",
    type: "Vulnerability Scan",
    progress: 75,
    status: "Running",
    time: "5 min ago",
  },
  {
    id: "SCAN-003",
    target: "https://staging.example.com",
    type: "Configuration Audit",
    progress: 100,
    status: "Completed",
    time: "10 min ago",
  },
  {
    id: "SCAN-004",
    target: "https://auth.example.com",
    type: "Authentication Bypass",
    progress: 0,
    status: "Failed",
    time: "15 min ago",
  },
];

function RecentScansTable({ className }: { className?: string }) {
  return (
    <Card className={cn("overflow-hidden", className)}>
      <div className="p-6 border-b border-zinc-800/50 flex items-center justify-between">
        <h3 className="font-bold text-zinc-200">Active & Recent Scans</h3>
        <Button variant="ghost" size="sm" className="text-xs">
          View All
        </Button>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-zinc-900/50 text-[10px] font-bold text-zinc-500 uppercase tracking-widest border-b border-zinc-800">
              <th className="px-6 py-4">Scan ID</th>
              <th className="px-6 py-4">Target</th>
              <th className="px-6 py-4">Module</th>
              <th className="px-6 py-4">Status</th>
              <th className="px-6 py-4">Time</th>
              <th className="px-6 py-4"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {recentScans.map((scan) => (
              <tr
                key={scan.id}
                className="group hover:bg-zinc-800/30 transition-colors"
              >
                <td className="px-6 py-4 text-sm font-mono text-zinc-400">
                  {scan.id}
                </td>
                <td className="px-6 py-4 text-sm font-semibold text-zinc-200">
                  {scan.target}
                </td>
                <td className="px-6 py-4 text-sm text-zinc-400">{scan.type}</td>
                <td className="px-6 py-4">
                  <Badge
                    variant={
                      scan.status === "Pending"
                        ? "info"
                        : scan.status === "Completed"
                          ? "success"
                          : "error"
                    }
                  >
                    {scan.status}
                  </Badge>
                </td>
                <td className="px-6 py-4 text-xs text-zinc-500">{scan.time}</td>
                <td className="px-6 py-4 text-right">
                  <button className="p-1 hover:bg-zinc-700 rounded transition-colors text-zinc-500">
                    <MoreVertical className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export default RecentScansTable;

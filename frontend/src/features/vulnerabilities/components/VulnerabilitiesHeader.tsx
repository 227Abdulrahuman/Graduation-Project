import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function VulnerabilitiesHeader() {
  return (
    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
      <div>
        <h1 className="text-3xl font-bold text-zinc-200 tracking-tight">
          Vulnerability Explorer
        </h1>
        <p className="text-zinc-500 mt-1">
          Aggregated security findings across all targets
        </p>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" size="sm">
          <Download className="w-4 h-4 mr-2" /> Export PDF
        </Button>
      </div>
    </div>
  );
}

import { useState } from "react";
import { Plus, Filter } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import SearchBar from "@/components/common/SearchBar";
import TargetsGrid from "../components/TargetsGrid";
import { type Target } from "../types";

const mockTargets: Target[] = [
  {
    id: "1",
    name: "Tesla, Inc.",
    type: "VDP",
    platform: "YesWeHack",
    program_url: "https://www.tesla.com",
    domains: ["tesla.com", "www.tesla.com"],
  },
  {
    id: "2",
    name: "Apple Global",
    type: "BBP",
    platform: "Bugcrowd",
    program_url: "https://www.apple.com",
    domains: ["apple.com", "www.apple.com"],
  },
  {
    id: "3",
    name: "SpaceX",
    type: "VDP",
    platform: "Hackerone",
    program_url: "https://www.spacex.com",
    domains: ["spacex.com", "www.spacex.com"],
  },
  {
    id: "4",
    name: "Meta Platforms",
    type: "BBP",
    platform: "Synack",
    program_url: "https://www.meta.com",
    domains: ["meta.com", "www.meta.com"],
  },
];

function TargetsPage() {
  const [search, setSearch] = useState("");
  // const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const onSelectTarget = (id: string) => {
    toast.success(`Target ${id} selected`);
  };

  return (
    <div className="mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">
            Targets & Scope
          </h1>
          <p className="text-zinc-500 mt-1">
            Manage your organizational attack surface
          </p>
        </div>
        <Button className="gap-2" onClick={() => console.log("Add Target")}>
          <Plus className="w-4 h-4" />
          Add Target
        </Button>
      </div>

      {/* Search & Filter Section */}
      <div className="flex flex-col sm:flex-row gap-4 items-center justify-between bg-zinc-900/30 p-4 rounded-xl border border-zinc-800/50">
        <SearchBar
          search={search}
          setSearch={setSearch}
          placeholder="Search targets..."
          className="w-full sm:w-96"
        />
        <div className="flex gap-2 w-full sm:w-auto">
          <Button
            variant="outline"
            size="sm"
            className="flex-1 sm:flex-initial"
          >
            <Filter className="w-4 h-4 mr-2" />
            Filters
          </Button>
        </div>
      </div>

      {/* Targets Grid */}
      <TargetsGrid onSelectTarget={onSelectTarget} targets={mockTargets} />

      {/* <AddTargetModal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onAdd={(data) => {
          toast.success(`Target ${data.name} added!`, {
            description: `${data.primaryDomain} has been registered for discovery.`,
          });
        }}
      /> */}
    </div>
  );
}

export default TargetsPage;

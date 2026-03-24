import { useState } from "react";
import VulnerabilitiesHeader from "../components/VulnerabilitiesHeader";
import VulnerabilityStats from "../components/VulnerabilityStats";
import VulnerabilityToolbar from "../components/VulnerabilityToolbar";
import VulnerabilitiesTable from "../components/VulnerabilitiesTable";
import { getVulns } from "../api";
import { useQuery } from "@tanstack/react-query";

export default function VulnerabilitiesPage() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [typeFilter, setTypeFilter] = useState("All");

  const {
    data: vulnerabilities,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: getVulns,
  });

  if (isLoading) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-8 animate-pulse">
        <div className="h-20 bg-zinc-900/50 rounded-xl" />
        <div className="grid grid-cols-2 md:grid-cols-4 lg:flex lg:flex-wrap gap-4">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="h-28 lg:flex-1 lg:min-w-[180px] bg-zinc-900/50 rounded-xl"
            />
          ))}
        </div>
        <div className="h-16 bg-zinc-900/50 rounded-xl" />
        <div className="h-[400px] bg-zinc-900/50 rounded-xl" />
      </div>
    );
  }

  if (isError || !vulnerabilities) {
    return (
      <div className="p-8 max-w-7xl mx-auto flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <h1 className="text-2xl font-bold text-red-500">
          Failed to load vulnerabilities
        </h1>
        <p className="text-zinc-500">
          Please check your connection and try again.
        </p>
        <p className="text-zinc-500">
          {error instanceof Error ? error.message : "Unknown error"}
        </p>
      </div>
    );
  }

  const filteredVulnerabilities = vulnerabilities.filter((v) => {
    const matchesSearch = v.title.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity =
      severityFilter === "All" || v.severity === severityFilter;
    const matchesType = typeFilter === "All" || v.type === typeFilter;
    return matchesSearch && matchesSeverity && matchesType;
  });

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      <VulnerabilitiesHeader />
      <VulnerabilityStats data={vulnerabilities} />
      <VulnerabilityToolbar
        search={search}
        setSearch={setSearch}
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
        typeFilter={typeFilter}
        setTypeFilter={setTypeFilter}
      />
      <VulnerabilitiesTable vulnerabilities={filteredVulnerabilities} />
    </div>
  );
}

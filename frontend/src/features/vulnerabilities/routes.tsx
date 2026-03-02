import type { RouteObject } from "react-router";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import { queryClient } from "@/lib/query-client";
import { getVulns } from "./api";

export const vulnerabilitiesRoutes: RouteObject[] = [
  {
    path: "vulnerabilities",
    element: <VulnerabilitiesPage />,
    loader: async () =>
      await queryClient.ensureQueryData({
        queryKey: ["vulnerabilities"],
        queryFn: getVulns,
      }),
  },
];

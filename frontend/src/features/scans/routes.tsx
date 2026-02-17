import type { RouteObject } from "react-router";
import ScansPage from "./pages/ScansPage";

export const scansRoutes: RouteObject[] = [
	{
		path: "scans",
		element: <ScansPage />,
	},
];
import type { RouteObject } from "react-router";
import TargetsPage from "./pages/TargetsPage";

export const targetsRoutes: RouteObject[] = [
	{
		path: "targets",
		element: <TargetsPage />,
	},
];
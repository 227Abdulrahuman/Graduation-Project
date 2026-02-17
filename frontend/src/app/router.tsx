import { createBrowserRouter } from "react-router";
import MainLayout from "@/components/layout/MainLayout";
import { dashboardRoutes } from "@/features/dashboard";
import { scansRoutes } from "@/features/scans";

export default createBrowserRouter([
	{
		path: "/",
		element: <MainLayout />,
		children: [
			...dashboardRoutes,
			...scansRoutes,
		],
	},
]);

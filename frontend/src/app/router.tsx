import { createBrowserRouter } from "react-router";
import MainLayout from "@/components/layout/MainLayout";
import { dashboardRoutes } from "@/features/dashboard";
import { scansRoutes } from "@/features/scans";
import { vulnerabilitiesRoutes } from "@/features/vulnerabilities";
import ErrorPage from "@/components/layout/ErrorPage";

export default createBrowserRouter([
	{
		path: "/",
		element: <MainLayout />,
		children: [
			...dashboardRoutes,
			...scansRoutes,
			...vulnerabilitiesRoutes,
		],
		errorElement: <ErrorPage />,
	},
]);

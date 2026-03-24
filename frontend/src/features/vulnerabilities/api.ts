
export interface Vulnerability {
    id: string;
    title: string;
    severity: string;
    target: string;
    type: string;
    age: string;
}

// Move mock data out of component to act as our "database"
const MOCK_VULNERABILITIES: Vulnerability[] = [
    {
        id: "VUL-102",
        title: "Subdomain Takeover (Azure)",
        severity: "Critical",
        target: "dev.tesla.com",
        type: "DNS",
        age: "2 days ago",
    },
    {
        id: "VUL-101",
        title: "Reflected XSS on /search",
        severity: "High",
        target: "shop.tesla.com",
        type: "Web",
        age: "1 week ago",
    },
    {
        id: "VUL-100",
        title: "Exposed Git Repository",
        severity: "Critical",
        target: "api.apple.com",
        type: "Config",
        age: "3 days ago",
    },
    {
        id: "VUL-099",
        title: "Weak SSL Cipher Suite",
        severity: "Low",
        target: "auth.meta.com",
        type: "SSL",
        age: "5 mins ago",
    },
    {
        id: "VUL-098",
        title: "SQL Injection in order_id",
        severity: "High",
        target: "staging.uber.com",
        type: "Web",
        age: "12 hrs ago",
    },
];

// 1. Simulate an API Fetch Request
export const getVulns = async (): Promise<Vulnerability[]> => {
    // --- REAL FETCH EXAMPLE ---
    // const response = await fetch('/api/vulnerabilities');
    // if (!response.ok) {
    //   throw new Error('Network response was not ok');
    // }
    // return response.json();

    // Simulate network latency (e.g. 800ms)
    await new Promise((resolve) => setTimeout(resolve, 800));
    return MOCK_VULNERABILITIES;
};

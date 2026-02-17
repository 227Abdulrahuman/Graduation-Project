```
src/
│
├── app/                    # App-level config
│   ├── router.jsx
│   ├── providers.jsx
│   └── store.js
│
├── features/
│   ├── dashboard/
│   │   ├── pages/
│   │   │   └── DashboardPage.jsx
│   │   ├── components/
│   │   │   └── StatsCard.jsx
│   │   ├── hooks/
│   │   ├── apis.ts
│   │   ├── routes.ts
│   │   └── index.ts
│   │
│   ├── targets/
│   │   ├── pages/
│   │   │   └── TargetsPage.jsx
│   │   ├── components/
│   │   │   ├── TargetTable.jsx
│   │   │   └── TargetModal.jsx
│   │   ├── hooks/
│   │   │   └── useTargets.js
│   │   ├── apis.ts
│   │   ├── routes.ts
│   │   └── index.ts
│   │
│   ├── subdomains/
│   ├── scans/
│   └── settings/
│
├── components/             # Shared reusable components
│   ├── layout/
│   │   ├── Sidebar.jsx
│   │   ├── Navbar.jsx
│   │   └── MainLayout.jsx
│   │
│   ├── ui/                 # Generic UI (buttons, inputs, modals)
│   │   ├── Button.jsx
│   │   ├── Table.jsx
│   │   └── Modal.jsx
│
├── hooks/                  # Global reusable hooks
│   ├── useAuth.js
│   └── useDebounce.js
│
├── services/               # Axios instance / global API config
│   └── apiClient.js
│
├── utils/
│   ├── constants.js
│   └── helpers.js
│
└── App.jsx

```
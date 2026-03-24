import { Search } from "lucide-react";

interface SearchProps {
  search: string;
  setSearch: (search: string) => void;
  placeholder: string;
  className: string;
}

function SearchBar({ search, setSearch, placeholder }: SearchProps) {
  return (
    <div className="relative w-full sm:w-96">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
      <input
        type="text"
        placeholder={placeholder}
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-full bg-zinc-950 border border-zinc-800 rounded-lg py-2 pl-10 pr-4 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500/50 transition-colors"
      />
    </div>
  );
}

export default SearchBar;

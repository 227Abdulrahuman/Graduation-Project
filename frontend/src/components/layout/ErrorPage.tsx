import { useRouteError, useNavigate } from   'react-router'

function ErrorPage() {
    const navigate = useNavigate()
    const error = useRouteError() as Error
    return (
    <div className="flex flex-col items-center justify-center h-screen bg-black text-zinc-100 font-sans">
        <h1 className="text-2xl font-bold">Something went wrong</h1>
        <p className="text-zinc-500">Please try again later</p>
        <p className="text-zinc-500">{error.message}</p>
        <button className="mt-4 px-4 py-2 bg-zinc-900 text-zinc-100 rounded-md cursor-pointer hover:bg-zinc-800 transition-colors" onClick={() => navigate("/")}>Go back to home</button>
    </div>
  )
}

export default ErrorPage
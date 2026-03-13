import './App.css'

function App() {
  return (
    <main className="checker-page">
      <h1 className="checker-title">Malicious Link Checker</h1>

      <div className="checker-center">
        <form className="checker-form" onSubmit={(event) => event.preventDefault()}>
          <label className="sr-only" htmlFor="url-input">
            Enter a link to check
          </label>
          <input
            id="url-input"
            className="checker-input"
            type="url"
            placeholder="https://example.com"
          />
          <button className="checker-button" type="submit">
            Enter
          </button>
        </form>
      </div>
    </main>
  )
}

export default App

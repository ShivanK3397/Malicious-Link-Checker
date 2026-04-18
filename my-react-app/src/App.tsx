import './App.css'
import axios from 'axios'

function App() {

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const urlInput = document.getElementById('url-input') as HTMLInputElement
    const url = urlInput.value
    try {
      const response = await axios.post('/check_link', { url })
      console.log(response.data)
    } catch (error) {
      console.error('Error checking link:', error)
    }
  }

  return (
    <main className="checker-page">
      <h1 className="checker-title">Malicious Link Checker</h1>

      <div className="checker-center">
        <form className="checker-form" onSubmit={onSubmit}>
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

import './App.css'
import axios from 'axios'
import { useState } from 'react'

function App() {
  const [result, setResult] = useState<string>('')
  
  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    setResult('')
    event.preventDefault()
    const urlInput = document.getElementById('url-input') as HTMLInputElement
    let url = urlInput.value
    if (!url) {
     
      return
    }
    console.log('Checking URL:', url)
    try {
      const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/check_link`, { url })
      
      console.log(response.data)
      if(response.data.prediction === 'benign'){
        setResult('benign')
      }
      else if(response.data.prediction === 'malware'){
        url = url.replace(/^https?:\/\//, '')
        //Add www. if not already present
        if (!/^www\./.test(url)) {
          url = 'www.' + url
        }
        
        try {
           const response = await axios.post(`${import.meta.env.VITE_API_BASE_URL}/api/check_link`, { url })
          setResult(response.data.prediction)
          console.log(response.data)
          
        } catch (error) {
          console.error('Error checking link:', error)
        }

      }
      else{
        setResult(response.data.prediction)
      }
      
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
            type="text"
            placeholder="www.example.com"
          />
          <button className="checker-button" type="submit">
            Submit
          </button>
          
        </form>
        <div>
            {result && (
              <p className="checker-result">
                This link is:{' '}
                <span
                  className={
                    result === 'benign'
                      ? 'checker-result-status checker-result-status--benign'
                      : 'checker-result-status checker-result-status--danger'
                  }
                >
                  {result}
                </span>
              </p>
            )}
          </div>
      </div>
      <footer className="checker-footer">
        <p>
          Made by 
          <a
            href="https://github.com/ShivanK3397"
            target="_blank"
            rel="noreferrer"> Shivan Kathir</a>
        </p>
      </footer>
    </main>
  )
}

export default App

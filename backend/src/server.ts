import express from 'express'
import cors from 'cors'

const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())

app.get('/api/hello', (req, res) => {
    res.send('Hello World!')
})

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`)
})

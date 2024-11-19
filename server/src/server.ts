import express from 'express';
import bodyParser from 'body-parser';
import { scanWebsite } from './controllers/scanController';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Routes
app.post('/api/scan', scanWebsite); // Use the function directly

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

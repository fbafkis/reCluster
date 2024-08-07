import express from 'express';
import path from 'path';
import nodesRouter from './routes/nodes';

const webApp = express();

// API Routes
webApp.use('/api', nodesRouter);

// Serve the status HTML page at the "/dashboard" route
webApp.use('/dashboard', express.static(path.join(__dirname, '../../../public')));

webApp.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../../../public', 'dashboard.html'));
});
webApp.get('/', (req, res) => {
  res.redirect('/dashboard');
});

export default webApp;

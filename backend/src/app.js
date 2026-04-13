const express = require('express');
const cors = require('cors');

const patientRoutes = require('./routes/patientRoutes');
const alertRoutes = require('./routes/alertRoutes');
const toolsRoutes = require('./routes/toolsRoutes');
const aiRoutes = require('./routes/aiRoutes');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.status(200).json({ message: 'API Express MVC is running' });
});

app.use('/api/patients', patientRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/tools', toolsRoutes);
app.use('/api/ai', aiRoutes);

module.exports = app;

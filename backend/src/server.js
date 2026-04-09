const path = require('path');
const dotenv = require('dotenv');

const envFiles = ['.env', '.env.example'];
for (const envFile of envFiles) {
  const result = dotenv.config({ path: path.resolve(__dirname, '..', envFile) });
  if (!result.error) {
    break;
  }
}

const app = require('./app');
const connectDB = require('./config/db');

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();

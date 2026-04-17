import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import ExpressMongoSanitize from 'express-mongo-sanitize';
import helmet from 'helmet';
import connectDB from './config/db';
import router from './routes/index';
import errorHandler from './shared/middleware/error';
import { setupHealthMonitoring } from './modules/health-metrics/index';
import dotenv from 'dotenv';

dotenv.config();
connectDB();

const app = express();

const allowedOrigins = [
  process.env.CLIENT_URL,
  process.env.ADMIN_URL,
  process.env.ORGANIZATION_URL,
];

const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow: boolean) => void) => {
      if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
          callback(null, true);  // Allow request
      } else {
          callback(new Error('Not allowed by CORS'), false);  // Deny request
      }
  },
  credentials: true,  // Allow cookies and credentials
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
};

app.use(express.json());

app.set('trust proxy', 1);
// Use the same corsOptions configuration consistently
app.use(cors(corsOptions));


app.use(cookieParser());
app.use(ExpressMongoSanitize());
app.use(helmet());

// Add pre-flight handling for all routes
app.options('*', cors(corsOptions));

// Health monitoring middleware
setupHealthMonitoring(app);

// Add pre-flight handling for all routes
app.options('*', cors(corsOptions));

// Health monitoring middleware
setupHealthMonitoring(app);

app.use(router);
app.use(errorHandler);

export default app;


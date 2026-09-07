import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { PrismaClient } from '@prisma/client';
import { encrypt, decrypt } from './utils/encryption';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

app.use(express.json());

// Swagger Setup
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: { title: 'SecureVault API', version: '1.0.0', description: 'RESTful API with JWT, RBAC, Prisma, AES Encryption' },
    components: {
      securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }
    }
  },
  apis: ['./src/app.ts'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Middleware: JWT Auth
const authenticate = (req: any, res: any, next: any) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; next();
  } catch { return res.status(401).json({ message: 'Invalid token' }); }
};

// Middleware: RBAC
const authorize = (roles: string[]) => (req: any, res: any, next: any) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: 'Forbidden: RBAC' });
  next();
};

/**
 * @swagger
 * /api/register:
 * post:
 * summary: Register user
 */
app.post('/api/register', async (req, res) => {
  const { email, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({ data: { email, password: hashed, role } });
  res.json(user);
});

/**
 * @swagger
 * /api/login:
 * post:
 * summary: Login with JWT
 */
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user ||!await bcrypt.compare(password, user.password)) return res.status(401).json({ message: 'Invalid creds' });
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

/**
 * @swagger
 * /api/vault:
 * post:
 * summary: Create encrypted vault item
 * security: [{ bearerAuth: [] }]
 */
app.post('/api/vault', authenticate, async (req: any, res) => {
  const { title, data } = req.body;
  const encryptedData = encrypt(data);
  const vault = await prisma.vaultItem.create({ data: { title, encryptedData, userId: req.user.id } });
  res.json(vault);
});

app.get('/api/vault', authenticate, async (req: any, res) => {
  const vaults = await prisma.vaultItem.findMany({ where: { userId: req.user.id } });
  const decrypted = vaults.map(v => ({...v, data: decrypt(v.encryptedData) }));
  res.json(decrypted);
});

// Admin only route for RBAC demo
app.get('/api/admin/users', authenticate, authorize(['ADMIN']), async (req, res) => {
  const users = await prisma.user.findMany();
  res.json(users);
});

app.listen(3000, () => console.log('SecureVault running on 3000 with JWT, RBAC, Prisma, Swagger'));

export default app;
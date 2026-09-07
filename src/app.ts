import express from 'express';
import { encrypt, decrypt } from './utils/encryption';
const app = express();
app.use(express.json());
app.post('/encrypt', (req,res) => { res.json(encrypt(req.body.text)); });
app.post('/decrypt', (req,res) => { const { enc, iv, tag } = req.body; res.json({ text: decrypt(enc, iv, tag) }); });
app.listen(3000, () => console.log('Server running'));
export default app;
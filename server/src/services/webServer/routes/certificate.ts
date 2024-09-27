// certificate.ts
import { Router } from 'express';
import path from 'path';

const certificateRouter = Router();

// Serve the SSH certificate as a downloadable file
certificateRouter.get('/getsshcertificate', (req, res) => {
  const certPath = path.join('/etc/recluster/certs', 'ssh.crt');

  // Send the file as a download
  res.download(certPath, 'ssh.crt', (err) => {
    if (err) {
      console.error('Error sending certificate:', err);
      res.status(500).send('Error fetching the SSH certificate');
    }
  });
});

export default certificateRouter;

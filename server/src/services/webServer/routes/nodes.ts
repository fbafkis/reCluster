import { Router } from 'express';
import { prisma } from '~/db';

const nodesRouter = Router();

nodesRouter.get('/nodes', async (req, res) => {
  try {
    const nodes = await prisma.node.findMany({
      include: {
        status: true,
        powerOnDevice: true,
        interfaces: true // Include interfaces in the response
      }
    });

    res.json({ nodes });
  } catch (error) {
    console.error('Error fetching nodes:', error);
    res.status(500).json({ error: 'Error fetching nodes' });
  }
});

export default nodesRouter;


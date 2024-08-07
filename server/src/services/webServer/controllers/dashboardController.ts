import { Request, Response } from 'express';
import { prisma } from '../../../db';

export const getNodes = async (req: Request, res: Response) => {
    try {
        const nodes = await prisma.node.findMany({
            include: {
                status: true,
                powerOnDevice: true,
            },
        });
        res.json({ nodes });
    } catch (error) {
        console.error('Error fetching nodes:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};


/* ! Always on top ! */
import 'reflect-metadata';
import 'json-bigint-patch';
import 'dotenv/config';
/*  */
import { container } from 'tsyringe';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import compress from '@fastify/compress';
import rateLimit from '@fastify/rate-limit';
import healthCheck from 'fastify-healthcheck';
import fastifyApollo, {
  fastifyApolloDrainPlugin
} from '@as-integrations/fastify';
import { ApolloServer } from '@apollo/server';
import express from 'express';
import { logger } from './logger';
import { context, formatError } from './helpers';
import { config } from './config';
import { prisma } from './db';
import { schema } from './graphql';
import { kubeconfig, NodeInformer } from './k8s';
import { Context } from './types';
import webApp from './services/webServer/webServer';
import { createServer } from 'http';

// Set timezone to UTC
process.env.TZ = 'Etc/UTC';

// Server
const server = Fastify();
// Apollo
const apollo = new ApolloServer<Context>({
  schema,
  formatError,
  plugins: [fastifyApolloDrainPlugin(server)]
});

// Dashboard server configuration
const dashboardPort = config.server.dashboardPort || 3000;
let dashboardServer: ReturnType<typeof createServer>;

// Dashboard server starting function
const startWebServer = (app: express.Express, port: number, name: string) => {
  const server = createServer(app);

  server.listen(port);

  server.on('listening', () => {
    logger.info(`${name} is running on http://localhost:${port}`);
  });

  server.on('error', (err) => {
    const error = err as { code?: string };
    if (error.code === 'EADDRINUSE') {
      logger.error(`Port ${port} is already in use. Trying another port...`);
      startWebServer(app, port + 1, name);
    } else {
      logger.error(`Error starting server: ${error}`);
    }
  });

  dashboardServer = server;
};

async function main() {
  // Database
  await prisma.$connect();
  logger.info(`Database connected`);

  // K8s
  kubeconfig.loadFromDefault();
  await container.resolve(NodeInformer).start();
  logger.info('K8s configured');

  // Apollo
  await apollo.start();
  logger.info('Apollo server started');

  // Server
  await server.register(rateLimit);
  await server.register(helmet, {
    crossOriginEmbedderPolicy: config.node.env !== 'development',
    contentSecurityPolicy: config.node.env !== 'development'
  });
  await server.register(cors);
  await server.register(compress);
  await server.register(healthCheck);
  await server.register(fastifyApollo(apollo), {
    path: config.graphql.path,
    context
  });
  const url = await server.listen({
    port: config.server.port,
    host: config.server.host
  });
  logger.info(`Server started at ${url}`);

  // Starting dashboard web server
  startWebServer(webApp, dashboardPort, 'Web server for the web dashboard');
}

// Terminator function
async function terminate(signal: NodeJS.Signals) {
  logger.warn(`Received '${signal}' signal`);

  // Container
  await container.dispose();
  // Database
  await prisma.$disconnect();
  // Apollo
  await apollo.stop();
  // Server
  await server.close();

  if (dashboardServer) {
    dashboardServer.close(() => {
      logger.info('Web server for the web dashboard closed.');
    });
  }
}

process.on('SIGTERM', () => terminate('SIGTERM'));
process.on('SIGINT', () => terminate('SIGINT'));

main().catch((error) => {
  logger.fatal(error instanceof Error ? error.message : error);
  throw error;
});

/*
 * MIT License
 *
 * Copyright (c) 2022-2023 Carlo Corradini
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import type { Prisma } from '@prisma/client';
import { delay, inject, injectable } from 'tsyringe';
import type {
  CreateNodeInput,
  UpdateNodeInput,
  UpdateStatusInput,
  WithRequired
} from '~/types';
import { NodeError } from '~/errors';
import { prisma, NodeStatusEnum } from '~/db';
import { logger } from '~/logger';
import { SSH } from '~/ssh';
import { isControllerNode } from '~/helpers';
import { TokenService, TokenTypes } from './TokenService';
import { CpuService } from './CpuService';
// eslint-disable-next-line import/no-cycle
import { NodePoolService } from './NodePoolService';
import { StatusService } from './StatusService';
import { K8sService } from './K8sService';
import { WoLService } from './WoLService';
import { SmartPlugService } from './SmartPlugService';
import { ButtonPressDeviceService } from './ButtonPressDeviceService';
import { exec } from 'child_process';

type CreateArgs = Omit<Prisma.NodeCreateArgs, 'include' | 'data'> & {
  data: CreateNodeInput;
};

type FindManyArgs = Omit<Prisma.NodeFindManyArgs, 'include' | 'cursor'> & {
  cursor?: string;
};

type FindUniqueArgs = Omit<Prisma.NodeFindUniqueArgs, 'include'>;

type FindUniqueOrThrowArgs = Omit<Prisma.NodeFindUniqueOrThrowArgs, 'include'>;

type UpdateArgs = Omit<Prisma.NodeUpdateArgs, 'include' | 'where' | 'data'> & {
  where: WithRequired<Pick<Prisma.NodeWhereUniqueInput, 'id'>, 'id'>;
  data: UpdateNodeInput;
};

type UnassignArgs = {
  where: WithRequired<Pick<Prisma.NodeWhereUniqueInput, 'id'>, 'id'>;
};

type ShutdownArgs = {
  where: WithRequired<Pick<Prisma.NodeWhereUniqueInput, 'id'>, 'id'>;
  status?: Pick<UpdateStatusInput, 'reason' | 'message'>;
};

type BootArgs = {
  where: WithRequired<Pick<Prisma.NodeWhereUniqueInput, 'id'>, 'id'>;
  status?: Pick<UpdateStatusInput, 'reason' | 'message'>;
};

@injectable()
export class NodeService {
  public constructor(
    @inject(CpuService)
    private readonly cpuService: CpuService,
    @inject(delay(() => NodePoolService))
    private readonly nodePoolService: NodePoolService,
    @inject(StatusService)
    private readonly statusService: StatusService,
    @inject(K8sService)
    private readonly k8sService: K8sService,
    @inject(TokenService)
    private readonly tokenService: TokenService,
    @inject(WoLService)
    private readonly wolService: WoLService,
    @inject(SmartPlugService)
    private readonly smartPlugService: SmartPlugService,
    @inject(ButtonPressDeviceService)
    private readonly buttonPressDeviceService: ButtonPressDeviceService
  ) {}

  public create(args: CreateArgs, prismaTxn?: Prisma.TransactionClient) {
    // eslint-disable-next-line @typescript-eslint/no-shadow
    const fn = async (prisma: Prisma.TransactionClient) => {
      logger.info(`Node service create: ${JSON.stringify(args)}`);

      // Create or update cpu
      const { id: cpuId } = await this.cpuService.upsert(
        {
          data: args.data.cpu,
          select: { id: true }
        },
        prisma
      );

      // Create or update node pool
      const { id: nodePoolId } = await this.nodePoolService.upsert(
        {
          data: {
            cpu: args.data.cpu.cores,
            memory: args.data.memory,
            roles: args.data.roles
          },
          select: { id: true }
        },
        prisma
      );

      // Prepare powerOnDevice data if strategy is not WOL or AO
      let powerOnDeviceData: any = undefined;
      if (args.data.powerOnDevice && args.data.powerOnStrategy !== "WOL" && args.data.powerOnStrategy !== "AO") {
        powerOnDeviceData = { create: args.data.powerOnDevice };
      }

      // Create the node
      const { id, roles } = await prisma.node.create({
        ...args,
        data: {
          ...args.data,
          name: `dummy.${args.data.address}`,
          status: {
            create: {
              status: NodeStatusEnum.ACTIVE,
              reason: 'NodeRegistered',
              message: 'Node registered',
              lastHeartbeat: new Date(),
              lastTransition: new Date()
            }
          },
          nodePool: { connect: { id: nodePoolId } },
          cpu: { connect: { id: cpuId } },
          storages: { createMany: { data: args.data.storages } },
          interfaces: {
            createMany: { data: args.data.interfaces }
          },
          powerOnDevice: powerOnDeviceData
        }
      });

      // Update node name
      const node = await this.update(
        {
          where: { id },
          data: {
            name: `${isControllerNode(roles) ? 'controller' : 'worker'}.${id}`
          }
        },
        prisma
      );

      // Generate token
      return this.tokenService.sign({
        type: TokenTypes.NODE,
        id: node.id,
        roles: node.roles,
        permissions: node.permissions
      });
    };

    return prismaTxn ? fn(prismaTxn) : prisma.$transaction(fn);
  }

  public findMany(
    args: FindManyArgs,
    prismaTxn: Prisma.TransactionClient = prisma
  ) {
    logger.debug(`Node service find many: ${JSON.stringify(args)}`);

    return prismaTxn.node.findMany({
      ...args,
      cursor: args.cursor ? { id: args.cursor } : undefined
    });
  }

  public findUnique(
    args: FindUniqueArgs,
    prismaTxn: Prisma.TransactionClient = prisma
  ) {
    logger.info(`Node service find unique: ${JSON.stringify(args)}`);

    return prismaTxn.node.findUnique({
      ...args,
      include: {
        status: true,
        powerOnDevice: true,
        interfaces: true
      }
    });
  }

  // public findUniqueOrThrow<T extends Prisma.NodeFindUniqueOrThrowArgs>(
  //   args: Prisma.SelectSubset<T, FindUniqueOrThrowArgs>,
  //   prismaTxn: Prisma.TransactionClient = prisma
  // ): Prisma.Prisma__NodeClient<Prisma.NodeGetPayload<T>> {
  //   logger.debug(`Node service find unique or throw: ${JSON.stringify(args)}`);

  //   return prismaTxn.node.findUniqueOrThrow({
  //     ...args,
  //     include: {
  //       status: true,
  //       powerOnDevice: true,
  //       interfaces: true
  //     }
  //   });
  // }

  public findUniqueOrThrow<T extends Prisma.NodeFindUniqueOrThrowArgs>(
    args: Prisma.SelectSubset<T, FindUniqueOrThrowArgs>,
    prismaTxn: Prisma.TransactionClient = prisma
  ): Prisma.Prisma__NodeClient<Prisma.NodeGetPayload<T>> {
    logger.info(`Node service find unique or throw: ${JSON.stringify(args)}`);

    const include = {
      status: true,
      powerOnDevice: true,
      interfaces: true
    };

    // Check if args already contains `select` or `include`
    if ('select' in args) {
      // If `select` is used, do not add `include`
      return prismaTxn.node.findUniqueOrThrow(args);
    } else if ('include' in args) {
      // Merge existing `include` with predefined `include` if `args.include` is defined
      return prismaTxn.node.findUniqueOrThrow({
        ...args,
        include: {
          ...include,
          ...(args.include ?? {}) // Use empty object if args.include is undefined
        }
      });
    } else {
      // Add `include` if neither `select` nor `include` are used
      return prismaTxn.node.findUniqueOrThrow({
        ...args,
        include
      });
    }
  }



  public update(args: UpdateArgs, prismaTxn?: Prisma.TransactionClient) {
    // eslint-disable-next-line @typescript-eslint/no-shadow
    const fn = async (prisma: Prisma.TransactionClient) => {
      logger.info(`Node service update: ${JSON.stringify(args)}`);

      // Extract data
      const { data } = args;

      if (data.status) {
        await this.statusService.update(
          {
            where: { id: args.where.id },
            data: data.status
          },
          prisma
        );

        delete data.status;
      }

      // Write data
      // eslint-disable-next-line no-param-reassign
      args.data = data;

      return prisma.node.update({
        ...args,
        data: { ...args.data, status: undefined }
      });
    };

    return prismaTxn ? fn(prismaTxn) : prisma.$transaction(fn);
  }

  public unassign(args: UnassignArgs, prismaTxn?: Prisma.TransactionClient) {
    // eslint-disable-next-line @typescript-eslint/no-shadow
    const fn = async (prisma: Prisma.TransactionClient) => {
      logger.info(`Node service unassign: ${JSON.stringify(args)}`);

      // Check if node exists and assigned to node pool
      const { nodePoolAssigned } = await this.findUniqueOrThrow(
        {
          where: { id: args.where.id },
          select: { nodePoolAssigned: true }
        },
        prisma
      );
      if (!nodePoolAssigned)
        throw new NodeError(
          `Node '${args.where.id}' is not assigned to any node pool`
        );

      // Delete K8s node
      await this.k8sService.deleteNode({ id: args.where.id });

      // Update
      return this.update(
        {
          where: { id: args.where.id },
          data: {
            nodePoolAssigned: false,
            status: {
              status: NodeStatusEnum.ACTIVE_DELETING,
              reason: 'NodeUnassign',
              message: 'Node unassign'
            }
          }
        },
        prisma
      );
    };

    return prismaTxn ? fn(prismaTxn) : prisma.$transaction(fn);
  }

  public shutdown(args: ShutdownArgs, prismaTxn?: Prisma.TransactionClient) {
    // eslint-disable-next-line @typescript-eslint/no-shadow
    const fn = async (prisma: Prisma.TransactionClient) => {
      logger.info(`Node service shutdown: ${JSON.stringify(args)}`);

      // Check if node exists and not assigned to node pool
      const node = await this.findUniqueOrThrow(
        {
          where: { id: args.where.id },
          select: {
            nodePoolId: true,
            nodePoolAssigned: true,
            address: true,
            powerOnStrategy: true,
            powerOnDevice: {
              select: { address: true, deviceType: true }
            }
          }
        },
        prisma
      );

      if (node.nodePoolAssigned) {
        throw new NodeError(
          `Node '${args.where.id}' is assigned to node pool ${node.nodePoolId}`
        );
      }

      // Handle different power strategies for shutdown
      switch (node.powerOnStrategy) {
        case 'AO':
          // Always On strategy
          logger.info(`Node '${args.where.id}' is configured as Always On (AO). It will not be shut down.`);
          break;

        case 'SP':
          // Smart Plug strategy
          if (!node.powerOnDevice || node.powerOnDevice.deviceType !== 'SMART_PLUG') {
            throw new NodeError(`Node '${args.where.id}' does not have a valid power on smart plug configured.`);
          }

          {
            // Perform shutdown via SSH
            const ssh = await SSH.connect({ host: node.address });
            await ssh.execCommand({
              command: 'sudo poweroff',
              disconnect: true
            });

            // Wait for node to be off
            await this.waitForNodeToBeOff(node.address);

            // Wait after ping unreachability for 15 seconds before turning off the smart plug to be sure that the node is really powered off gracefully
            await new Promise((resolve) => setTimeout(resolve, 15000));
            await this.smartPlugService.powerOff(node.powerOnDevice.address, args.where.id);
          }
          break;

        case 'WOL':
        case 'BPD':
          {
            // Wake on LAN and Button Press Device strategy
            // Perform shutdown via SSH
            const ssh = await SSH.connect({ host: node.address });
            await ssh.execCommand({
              command: 'sudo poweroff',
              disconnect: true
            });

            // Update node status
            await this.update(
              {
                where: { id: args.where.id },
                data: {
                  status: {
                    status: NodeStatusEnum.INACTIVE,
                    reason: args.status?.reason ?? 'NodeShutdown',
                    message: args.status?.message ?? 'Node shutdown'
                  }
                }
              },
              prisma
            );
          }
          break;

        default:
          throw new NodeError(`Node '${args.where.id}' has an unknown power on strategy '${node.powerOnStrategy}'.`);
      }
    };

    return prismaTxn ? fn(prismaTxn) : prisma.$transaction(fn);
  }

  public boot(args: BootArgs, prismaTxn?: Prisma.TransactionClient) {
    // eslint-disable-next-line @typescript-eslint/no-shadow
    const fn = async (prisma: Prisma.TransactionClient) => {
      logger.info(`Node service boot: ${JSON.stringify(args)}`);

      // Check if node exists and not assigned to node pool
      const node = await this.findUniqueOrThrow(
        {
          where: { id: args.where.id },
          select: {
            nodePoolId: true,
            nodePoolAssigned: true,
            powerOnStrategy: true,
            address: process.platform === 'win32',
            interfaces: {
              select: { address: true, controller: true, wol: true }
            },
            powerOnDevice: {
              select: { address: true, deviceType: true }
            }
          }
        },
        prisma
      );

      if (node.nodePoolAssigned)
        throw new NodeError(
          `Node '${args.where.id}' is assigned to node pool ${node.nodePoolId}`
        );

      // Handle different power on strategies
      switch (node.powerOnStrategy) {
        case 'WOL':
          const controllerInterface = node.interfaces.find(intf => intf.controller);

          if (!controllerInterface) {
            throw new NodeError(`Node '${args.where.id}' does not have a controller interface with WoL capability`);
          }

          // Wake on LAN strategy using the controller interface
          await this.wolService.wake({
            mac: controllerInterface.address,
            opts: {
              ...(process.platform === 'win32' && { address: node.address })
            }
          });
          break;

        case 'AO':
          // Always On strategy
          logger.info(`Node '${args.where.id}' power on strategy is configured as Always On (AO). Nothing to do.`);
          break;

        case 'SP':
          // Smart Plug strategy
          if (!node.powerOnDevice || node.powerOnDevice.deviceType !== 'SMART_PLUG')
            throw new NodeError(`Node '${args.where.id}' does not have a valid Smart Plug configured.`);

          // Add logic to handle Smart Plug power on
          await this.smartPlugService.powerOn(node.powerOnDevice.address, args.where.id);
          break;

        case 'BPD':
          // Button Press Device strategy
          if (!node.powerOnDevice || node.powerOnDevice.deviceType !== 'BUTTON_PRESS')
            throw new NodeError(`Node '${args.where.id}' does not have a valid Button Press Device configured.`);

          // Add logic to handle Button Press Device power on
          await this.buttonPressDeviceService.pressButton(node.powerOnDevice.address, args.where.id);
          break;

        default:
          throw new NodeError(`Node '${args.where.id}' has an unknown power on strategy '${node.powerOnStrategy}'.`);
      }

      // Update node status
      await this.update(
        {
          where: { id: args.where.id },
          data: {
            nodePoolAssigned: true,
            status: {
              status: NodeStatusEnum.BOOTING,
              reason: args.status?.reason ?? 'NodeBoot',
              message: args.status?.message ?? 'Node boot'
            }
          }
        },
        prisma
      );
    };

    return prismaTxn ? fn(prismaTxn) : prisma.$transaction(fn);
  }

  // Aux method to wait for node to be off and check ping reachability
  private async waitForNodeToBeOff(address: string): Promise<void> {
    const pingNode = (): Promise<boolean> => {
      return new Promise((resolve) => {
        exec(`ping -c 1 ${address}`, (error) => {
          resolve(!error);
        });
      });
    };

    // Wait for a maximum of 1 minute, checking every 10 seconds
    for (let i = 0; i < 6; i++) {
      const isNodeOn = await pingNode();
      if (!isNodeOn) {
        logger.info(`Node at ${address} is now off.`);
        return;
      }
      logger.info(`Node at ${address} is still on, checking again in 10 seconds...`);
      await new Promise((resolve) => setTimeout(resolve, 10000));
    }

    logger.warn(`Node at ${address} did not go off after 2 minutes and is still reachable via ping.`);
    throw new NodeError(`Node at ${address} did not shut down within the expected time.`);
  }
}

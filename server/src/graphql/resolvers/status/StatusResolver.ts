/*
 * MIT License
 *
 * Copyright (c) 2022-2022 Carlo Corradini
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

import type * as Prisma from '@prisma/client';
import { Args, Directive, Mutation, Query, Resolver } from 'type-graphql';
import { inject, injectable } from 'tsyringe';
import { StatusService, TokenPayload, TokenTypes } from '~/services';
import { Status } from '../../entities';
import {
  FindUniqueStatusArgs,
  FindManyStatusArgs,
  CreateStatusArgs
} from '../../args';
import { Applicant } from '../../decorators';

@Resolver(Status)
@injectable()
export class StatusResolver {
  public constructor(
    @inject(StatusService)
    private readonly statusService: StatusService
  ) {}

  @Query(() => [Status], { description: 'List of Statuses' })
  async statuses(@Args() args: FindManyStatusArgs): Promise<Prisma.Status[]> {
    return this.statusService.findMany(args);
  }

  @Query(() => Status, {
    nullable: true,
    description: 'Status matching the identifier'
  })
  async status(
    @Args() args: FindUniqueStatusArgs
  ): Promise<Prisma.Status | null> {
    return this.statusService.findUnique(args);
  }

  @Mutation(() => Status, { description: 'Create a new status' })
  @Directive(`@auth(type: "${TokenTypes.NODE}")`)
  async createStatus(
    @Args() args: CreateStatusArgs,
    @Applicant() applicant: TokenPayload
  ): Promise<Prisma.Status> {
    return this.statusService.create({
      data: { ...args.data, nodeId: applicant.id }
    });
  }
}

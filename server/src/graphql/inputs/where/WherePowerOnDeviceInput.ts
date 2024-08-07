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
import { Field, InputType } from 'type-graphql';
import {
  BigIntFilter,
  StringFilter,
  WoLFlagEnumListFilter,
  TimestampFilter,
  UuidFilter
} from '../filters';
import { PowerOnDeviceTypeEnumFilter } from '../filters/PowerOnDeviceTypeEnumListFilter';

@InputType({ isAbstract: true, description: 'Interface where input' })
export class WherePowerOnDeviceInput
  implements
    Partial<
      Omit<Prisma.PowerOnDeviceWhereInput, 'AND' | 'OR' | 'NOT' | 'node'>
    >
{
  @Field({ nullable: true, description: 'Power on device identifier' })
  id?: UuidFilter;

  @Field({ nullable: true, description: 'Node identifier' })
  nodeId?: StringFilter;

  @Field({ nullable: true, description: 'Power on device type' })
  deviceType?: PowerOnDeviceTypeEnumFilter;

  @Field({ nullable: true, description: 'Power on device IP address' })
  address?: StringFilter;

  @Field({ nullable: true, description: 'Creation timestamp' })
  createdAt?: TimestampFilter;

  @Field({ nullable: true, description: 'Update timestamp' })
  updatedAt?: TimestampFilter;
}
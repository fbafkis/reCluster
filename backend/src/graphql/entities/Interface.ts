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

import { GraphQLID } from 'graphql';
import { Interface as InterfacePrisma } from '@prisma/client';
import { Field, ObjectType, registerEnumType } from 'type-graphql';
import {
  GraphQLBigInt,
  GraphQLMAC,
  GraphQLNonEmptyString
} from 'graphql-scalars';

export enum InterfaceWol {
  a = 'a',
  b = 'b',
  d = 'd',
  g = 'g',
  m = 'm',
  p = 'p',
  s = 's',
  u = 'u'
}

registerEnumType(InterfaceWol, {
  name: 'InterfaceWol',
  description: 'Interface Wake On Lan flag'
});

@ObjectType({ description: 'Interface' })
export class Interface implements InterfacePrisma {
  @Field(() => GraphQLID, { description: 'Interface identifier' })
  id!: string;

  @Field(() => GraphQLID, { description: 'Node identifier' })
  nodeId!: string;

  @Field(() => GraphQLNonEmptyString, { description: 'Interface name' })
  name!: string;

  @Field(() => GraphQLMAC, { description: 'Interface MAC address' })
  address!: string;

  @Field(() => GraphQLBigInt, { description: 'Interface speed' })
  speed!: bigint;

  @Field(() => [InterfaceWol], { description: 'Interface Wake On Lan flags' })
  wol!: InterfaceWol[];
}

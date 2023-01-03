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
import { NodePermissionEnum } from '~/db';

@InputType({
  isAbstract: true,
  description: 'Node permissions filter'
})
export class NodePermissionEnumListFilter
  implements Prisma.EnumNodePermissionEnumNullableListFilter
{
  @Field(() => NodePermissionEnum, {
    nullable: true,
    description: 'Node permissions exists in the list'
  })
  has?: NodePermissionEnum;

  @Field(() => [NodePermissionEnum], {
    nullable: true,
    description: 'Every Node permission exists in the list'
  })
  hasEvery?: NodePermissionEnum[];

  @Field(() => [NodePermissionEnum], {
    nullable: true,
    description: 'At least one Node permission exists in the list'
  })
  hasSome?: NodePermissionEnum[];

  @Field({ nullable: true, description: 'List is empty' })
  isEmpty?: boolean;

  @Field(() => [NodePermissionEnum], {
    nullable: true,
    description: 'List matches the given Node permission list exactly'
  })
  equals?: NodePermissionEnum[];
}

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

import { GraphQLBoolean } from 'graphql';
import { Field, InputType } from 'type-graphql';
import { GraphQLNonEmptyString, GraphQLNonNegativeInt } from 'graphql-scalars';
import type { UpdateNodePoolInput as IUpdateNodePoolInput } from '~/types';

@InputType({ description: 'Update Node pool input' })
export class UpdateNodePoolInput implements IUpdateNodePoolInput {
  @Field(() => GraphQLNonEmptyString, {
    nullable: true,
    description: 'Node pool name'
  })
  name?: string;

  @Field(() => GraphQLBoolean, {
    nullable: true,
    description: 'Node pool auto scale flag'
  })
  autoScale?: boolean;

  @Field(() => GraphQLNonNegativeInt, {
    nullable: true,
    description: 'Node pool node count'
  })
  count?: number;

  @Field(() => GraphQLNonNegativeInt, {
    nullable: true,
    description: 'Node pool minimum number of nodes'
  })
  minNodes?: number;
}

import { Transport } from './transport.js';
import type { AggregateOp, AggregateResult } from './types.js';

export class AggregateClient {
  constructor(private transport: Transport) {}

  async sum(tag: string, field: string): Promise<AggregateResult> {
    return this.query(tag, 'sum', field);
  }

  async avg(tag: string, field: string): Promise<AggregateResult> {
    return this.query(tag, 'avg', field);
  }

  async count(tag: string): Promise<AggregateResult> {
    return this.query(tag, 'count');
  }

  async min(tag: string, field: string): Promise<AggregateResult> {
    return this.query(tag, 'min', field);
  }

  async max(tag: string, field: string): Promise<AggregateResult> {
    return this.query(tag, 'max', field);
  }

  async query(tag: string, op: AggregateOp, field?: string): Promise<AggregateResult> {
    const params = new URLSearchParams({ tag, op });
    if (field) params.set('field', field);
    return this.transport.requestJson<AggregateResult>(`/v1/memory/aggregate?${params.toString()}`);
  }

}

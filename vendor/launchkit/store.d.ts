export interface Store {
  get(key: string): Promise<any | null>;
  set(key: string, value: any): Promise<void>;
  del(key: string): Promise<void>;
  list(prefix?: string): Promise<string[]>;
}
export function memoryStore(): Store;
export function prefixed(store: Store, prefix: string): Store;
export function keyPart(s: unknown): string;

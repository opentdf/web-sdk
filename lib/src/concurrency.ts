type LabelledSuccess<T> = { lid: string; value: Promise<T> };
type LabelledFailure = { lid: string; e: any };

async function labelPromise<T>(label: string, promise: Promise<T>): Promise<LabelledSuccess<T>> {
  try {
    const value = await promise;
    return { lid: label, value: Promise.resolve(value) };
  } catch (e) {
    throw { lid: label, e };
  }
}

// Pooled variant of Promise.all; implements most of the logic of the real all,
// but with a pool size of n. Rejects on first reject, or returns a list
// of all successful responses. Operates with at most n 'active' promises at a time.
// For tracking purposes, all promises must have a unique identifier.
export async function allPool<T>(n: number, p: Record<string, Promise<T>>): Promise<Awaited<T>[]> {
  const pool: Record<string, Promise<LabelledSuccess<T>>> = {};
  const resolved: Awaited<T>[] = [];
  for (const [id, job] of Object.entries(p)) {
    // while the size of jobs to do is greater than n,
    // let n jobs run and take the first one to finish out of the pool
    pool[id] = labelPromise(id, job);
    if (Object.keys(pool).length > n - 1) {
      const promises = Object.values(pool);
      try {
        const { lid, value } = await Promise.race(promises);
        resolved.push(await value);
        console.log(`succeeded on promise ${lid}`, value);
        delete pool[lid];
      } catch (err) {
        const { lid, e } = err as LabelledFailure;
        console.warn(`failed on promise ${lid}`, err);
        throw e;
      }
    }
  }
  try {
    for (const labelled of await Promise.all(Object.values(pool))) {
      console.log(`real.all succeeded on promise ${labelled.lid}`, labelled);
      resolved.push(await labelled.value);
    }
  } catch (err) {
    if ('lid' in err && 'e' in err) {
      throw err.e;
    } else {
      throw err;
    }
  }
  return resolved;
}

// Pooled variant of promise.any; implements most of the logic of the real any,
// but with a pool size of n, and returns the first successful promise,
// operating with at most n 'active' promises at a time.
export async function anyPool<T>(n: number, p: Record<string, Promise<T>>): Promise<Awaited<T>> {
  const pool: Record<string, Promise<LabelledSuccess<T>>> = {};
  const rejections = [];
  for (const [id, job] of Object.entries(p)) {
    // while the size of jobs to do is greater than n,
    // let n jobs run and take the first one to finish out of the pool
    pool[id] = labelPromise(id, job);
    if (Object.keys(pool).length > n - 1) {
      const promises = Object.values(pool);
      try {
        const { lid, value } = await Promise.race(promises);
        console.log(`any succeeded on promise ${lid}`, value);
        return await value;
      } catch (error) {
        const { lid, e } = error;
        rejections.push(e);
        delete pool[lid];
        console.log(`any failed on promise ${lid}`, e);
      }
    }
  }
  try {
    const { lid, value } = await Promise.any(Object.values(pool));
    console.log(`real.any succeeded on promise ${lid}`);
    return await value;
  } catch (errors) {
    console.log(`real.any failed`, errors);
    if (errors instanceof AggregateError) {
      for (const error of errors.errors) {
        if ('lid' in error && 'e' in error) {
          rejections.push(error.e);
        } else {
          rejections.push(error);
        }
      }
    } else {
      rejections.push(errors);
    }
  }
  throw new AggregateError(rejections);
}

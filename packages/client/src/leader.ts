import type { LeaderCoordinator, LeaderResult, LockManagerLike } from './types.js'

const DEFAULT_LEADER_LOCK_NAME = 'sigil_refresh_lock'

async function runWithOptionalLock<T>(
  locks: LockManagerLike | undefined,
  lockName: string,
  task: () => Promise<T>,
): Promise<LeaderResult<T>> {
  if (locks === undefined) {
    const value = await task()
    return { executed: true, value }
  }

  return locks.request<LeaderResult<T>>(
    lockName,
    { ifAvailable: true },
    async (lock): Promise<LeaderResult<T>> => {
      if (lock === null) {
        return { executed: false }
      }

      return {
        executed: true,
        value: await task(),
      }
    },
  )
}

export function createLeaderCoordinator(config?: {
  readonly lockName?: string | undefined
  readonly locks?: LockManagerLike | undefined
}): LeaderCoordinator {
  const lockName = config?.lockName ?? DEFAULT_LEADER_LOCK_NAME
  const navigatorLike = globalThis.navigator as
    | (Navigator & { locks?: LockManagerLike })
    | undefined
  const locks: LockManagerLike | undefined = config?.locks ?? navigatorLike?.locks
  let closed = false
  // A single in-flight slot deduplicates concurrent refreshes for the same coordinator
  // instance. The cast is intentional because callers provide the matching task/result type.
  let inFlight: Promise<LeaderResult<unknown>> | null = null

  return {
    async runAsLeader<T>(task: () => Promise<T>): Promise<LeaderResult<T>> {
      if (closed) {
        throw new Error('Leader coordinator is closed')
      }

      if (inFlight !== null) {
        return inFlight as Promise<LeaderResult<T>>
      }

      const operation = runWithOptionalLock(locks, lockName, task)

      inFlight = operation as Promise<LeaderResult<unknown>>

      try {
        return await operation
      } finally {
        inFlight = null
      }
    },

    close(): void {
      closed = true
      inFlight = null
    },
  }
}

export { DEFAULT_LEADER_LOCK_NAME }

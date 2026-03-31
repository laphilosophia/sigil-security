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

  return {
    async runAsLeader<T>(task: () => Promise<T>): Promise<LeaderResult<T>> {
      if (closed) {
        throw new Error('Leader coordinator is closed')
      }

      return runWithOptionalLock(locks, lockName, task)
    },

    close(): void {
      closed = true
    },
  }
}

export { DEFAULT_LEADER_LOCK_NAME }

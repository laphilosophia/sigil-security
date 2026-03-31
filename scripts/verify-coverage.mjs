import { readFile } from 'node:fs/promises'

const coverageSummaryPath = new URL('../coverage/coverage-summary.json', import.meta.url)

const thresholds = {
  core: { lines: 95, branches: 90 },
  policy: { lines: 90, branches: 85 },
  runtime: { lines: 85, branches: 80 },
  client: { lines: 85, branches: 80 },
  ops: { lines: 80, branches: 75 },
}

function normalizePath(filePath) {
  return filePath.replaceAll('\\', '/')
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function isPackageSourcePath(filePath, packageName) {
  const normalizedPath = normalizePath(filePath)
  const pattern = new RegExp(`(^|/)packages/${escapeRegex(packageName)}/src/`)
  return pattern.test(normalizedPath)
}

function formatPercent(value) {
  return value.toFixed(2)
}

function aggregateMetrics(entries) {
  let coveredLines = 0
  let totalLines = 0
  let coveredBranches = 0
  let totalBranches = 0

  for (const metrics of entries) {
    coveredLines += metrics.lines.covered
    totalLines += metrics.lines.total
    coveredBranches += metrics.branches.covered
    totalBranches += metrics.branches.total
  }

  return {
    lines: totalLines === 0 ? 100 : (coveredLines / totalLines) * 100,
    branches: totalBranches === 0 ? 100 : (coveredBranches / totalBranches) * 100,
  }
}

let rawSummary

try {
  rawSummary = await readFile(coverageSummaryPath, 'utf8')
} catch (error) {
  if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
    console.error('Coverage summary not found. Run pnpm test:coverage to generate it.')
    process.exit(1)
  }

  throw error
}

const parsedSummary = JSON.parse(rawSummary)
const fileEntries = Object.entries(parsedSummary).filter(([key]) => key !== 'total')

const failures = []

for (const [pkg, target] of Object.entries(thresholds)) {
  const packageEntries = fileEntries
    .filter(([filePath]) => isPackageSourcePath(filePath, pkg))
    .map(([, metrics]) => metrics)

  if (packageEntries.length === 0) {
    failures.push(
      `${pkg}: no source files found in coverage summary`,
    )
    continue
  }

  const metrics = aggregateMetrics(packageEntries)
  const linePass = metrics.lines >= target.lines
  const branchPass = metrics.branches >= target.branches

  console.log(
    [
      pkg.padEnd(7),
      `lines ${formatPercent(metrics.lines)}% / ${target.lines}%`,
      `branches ${formatPercent(metrics.branches)}% / ${target.branches}%`,
    ].join(' | '),
  )

  if (!linePass || !branchPass) {
    failures.push(
      `${pkg}: lines ${formatPercent(metrics.lines)}% (target ${target.lines}%), branches ${formatPercent(metrics.branches)}% (target ${target.branches}%)`,
    )
  }
}

if (failures.length > 0) {
  console.error('\nCoverage target failures:')
  for (const failure of failures) {
    console.error(`- ${failure}`)
  }
  process.exit(1)
}

console.log('\nCoverage targets satisfied for all packages.')

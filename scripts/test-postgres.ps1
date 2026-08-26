[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$project = 'athena-disposable-' + [guid]::NewGuid().ToString('N')
$repo = Split-Path -Parent $PSScriptRoot

try {
    docker compose --project-name $project --file "$repo/compose.test.yaml" run --rm postgres-tests
    if ($LASTEXITCODE -ne 0) {
        throw "Disposable PostgreSQL tests failed with exit code $LASTEXITCODE"
    }
}
finally {
    if ($project -notmatch '^athena-disposable-[0-9a-f]{32}$') {
        throw "Refusing to clean an unexpected Compose project name"
    }
    docker compose --project-name $project --file "$repo/compose.test.yaml" down --volumes
}

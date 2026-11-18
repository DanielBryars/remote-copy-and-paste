# Builds release binaries for Windows (native) and Linux (static musl, via WSL)
# into .\dist. Requires: Rust (windows-gnu) + MinGW on Windows, Rust in WSL
# with the x86_64-unknown-linux-musl target.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force dist | Out-Null

cargo build --release
Copy-Item target\release\clipshare.exe dist\clipshare-windows-x86_64.exe

# Build from a copy on the Linux filesystem: much faster than /mnt/e.
$src = (wsl -d Ubuntu -- wslpath -a ($PSScriptRoot -replace '\\', '/')).Trim()
wsl -d Ubuntu -- bash -c "mkdir -p ~/clipshare && cp -r '$src/Cargo.toml' '$src/Cargo.lock' '$src/src' '$src/tests' '$src/examples' ~/clipshare/ && cd ~/clipshare && ~/.cargo/bin/cargo build --release --target x86_64-unknown-linux-musl && cp target/x86_64-unknown-linux-musl/release/clipshare '$src/dist/clipshare-linux-x86_64'"
if ($LASTEXITCODE -ne 0) { throw "Linux build failed" }

Get-ChildItem dist | Format-Table Name, Length

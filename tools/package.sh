#!/bin/bash
# Pubblica l'exe win-x64 e crea i due zip con la versione: tools/package.sh 1.4.2
set -e
V=$1; [ -n "$V" ] || { echo "uso: tools/package.sh <versione>"; exit 2; }
cd "$(dirname "$0")/.."
export PATH=/home/claude/.dotnet:$PATH DOTNET_ROOT=/home/claude/.dotnet DOTNET_CLI_TELEMETRY_OPTOUT=1
if grep -rIl -E "84\.38\." --exclude-dir=bin --exclude-dir=obj --exclude-dir=publish --exclude-dir=dist --exclude-dir=Sessioni --exclude-dir=.git . ; then echo "dati cliente nei sorgenti"; exit 1; fi
rm -rf publish && dotnet publish src/PhpVulnScanner.App -c Release -r win-x64 -o publish -p:DebugType=none 2>&1 | grep -E "rror CS" && exit 1
test -f publish/PhpVulnScanner.exe
P=dist/pkg; rm -rf $P; mkdir -p $P/examples
cp publish/PhpVulnScanner.exe $P/; cp -r publish/lang publish/data $P/
cp LEGGIMI_v$V.txt README.md README.it.md LICENSE CLAUDE.md THIRD-PARTY-NOTICES.txt CHANGELOG.md $P/
cp src/PhpVulnScanner.App/Help/Guida.html $P/Guida_PhpVulnScanner_v$V.html; cp src/PhpVulnScanner.App/Help/Guide.html $P/Guide_PhpVulnScanner_v$V.html
cp examples/bersagli_esempio_v1.0.txt $P/examples/
OUT=/home/claude; rm -f $OUT/PhpVulnScanner_v${V}_win-x64.zip $OUT/PhpVulnScanner_v${V}_sources.zip
(cd $P && zip -qr -9 $OUT/PhpVulnScanner_v${V}_win-x64.zip .)
S=$(mktemp -d); tar --exclude='./.git' --exclude='./publish' --exclude='./dist' --exclude='./Sessioni' --exclude='*/bin' --exclude='*/obj' --exclude='./PhpVulnScanner.settings.json' --exclude='./crash.log' -cf - . | (cd $S && tar xf -)
(cd $S && zip -qr -9 $OUT/PhpVulnScanner_v${V}_sources.zip .); rm -rf $S
ls -la $OUT/PhpVulnScanner_v${V}_*.zip; sha256sum $OUT/PhpVulnScanner_v${V}_*.zip

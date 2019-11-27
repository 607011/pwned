#!/usr/bin/bash

DOWNLOAD_DIR=downloaded
mkdir -p $DOWNLOAD_DIR

for i in {1..4343}; do
  curl "https://hashes.org/download.php?type=found&hashlistId=${i}" \
   -sS \
   -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0" \
   -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
   -H "Referer: https://hashes.org/" \
   -H "Cookie: PHPSESSID=59vv2ucu6qndtusilvrgf55h55" \
   -o "${DOWNLOAD_DIR}/${i}.txt"
done

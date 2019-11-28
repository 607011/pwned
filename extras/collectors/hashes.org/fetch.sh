#!/usr/bin/bash

if [ "$(uname)" = "Darwin" ]; then
  function file_size() {
    stat "$1" | cut -d" " -f 8
  }
elif [ "$(uname)" = "Linux" ]; then
  function file_size() {
    stat -c%s "$1"
  }
else
  echo "Unsupported platform"
fi

. .fetch.config

if [ "${DOWNLOAD_DIR}" = "" ]; then
  DOWNLOAD_DIR=downloaded
fi
if [ "${CONVERTED_DIR}" = "" ]; then
  CONVERTED_DIR=converted
fi
if [ "${COOKIE_JAR}" = "" ]; then
  COOKIE_JAR=cookies.txt
fi
if [ "${LATEST}" = "" ]; then
  LATEST=.latest
fi
if [ "${RAM}" = "" ]; then
  RAM=16384
fi
if [ "${THREADS}" = "" ]; then
  THREADS=4
fi
if [ "${MERGED_MD5}" = "" ]; then
  MERGED_MD5=merged.md5
fi
if [ "${CONVERTER}" = "" ]; then
  CONVERTER=pwned-converter-cli
fi
if [ "${MERGER}" = "" ]; then
  MERGER=pwned-merger-cli
fi

mkdir -p $DOWNLOAD_DIR

function usage() {
  echo "Usage: fetch.sh [<first index>] <last index>"
}

function save {
  echo $LAST_ID > $LATEST
}

function ctrl_c()
{
  stty sane
  save
  exit
}

function get_key() {
  local old_tty_settings=$(stty -g)
  stty -icanon time 0 min 0
  echo $(head -c1)
  stty "$old_tty_settings"
}

trap ctrl_c SIGINT

if [[ -n $1 && -n $2 ]]; then
  FROM=$1
  TO=$2
elif [[ -n $1 ]]; then
  FROM=`head -1 ${LATEST}`
  TO=$1
fi

if [[ -z $FROM || -z $TO ]]; then
  usage
  exit 1
fi

echo
echo "You're about to download plaintext password files from hashes.org."
echo "Clean download directory ('${DOWNLOAD_DIR}') before proceeding? (y/n)"
read -s -n 1 reply
if [[ "$reply" = "y" ]]; then
  echo "Deleting ..."
  rm "${DOWNLOAD_DIR}"/*.txt
fi

echo "Fetching cookies ..."
curl -sSI --cookie-jar $COOKIE_JAR "https://hashes.org/leaks.php" > /dev/null

LAST_ID=${FROM}

echo "Fetching password lists from ${FROM} to ${TO} ... (Press q to quit.)"
for ID in `seq ${FROM} ${TO}`; do
  echo -n " #${ID} ... "
  OUTPUT_FILE="${DOWNLOAD_DIR}/${ID}.txt"
  curl "https://hashes.org/download.php?type=found&hashlistId=${ID}" \
    -sS \
    --cookie-jar $COOKIE_JAR \
    -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0" \
    -H "Referer: https://hashes.org/" \
    -o "${OUTPUT_FILE}"
  CONTENTS=`head -1 "${OUTPUT_FILE}"`
  if [ "$CONTENTS" = "Invalid hashlist!" ]; then
    echo "INVALID"
    rm "${OUTPUT_FILE}"
  elif [ "$CONTENTS" = "Hashlist is deleted!" ]; then
    echo "DELETED"
    rm "${OUTPUT_FILE}"
  elif [ "$(file_size ${OUTPUT_FILE})" -eq 0 ]; then
    echo "EMPTY"
    rm "${OUTPUT_FILE}"
  else
    echo "OK"
    LAST_ID=$ID
  fi
  if [ "$(get_key)" = "q" ]; then
    break
  fi
done

stty sane
save

echo
echo "Download finished."
echo "Do you want to convert the downloaded files to MD5:count files?"
echo "This will delete all *.md5 files already present in ${CONVERTED_DIR}."
echo "Okay? (y/n)"
read -s -n 1 reply
if [[ "$reply" = "y" ]]; then
  rm "${CONVERTED_DIR}"/*.md5
  ${CONVERTER} -S "${DOWNLOAD_DIR}" -D "${CONVERTED_DIR}" --threads=$THREADS --auto-md5 --auto-hex --ram=$RAM
  echo
  echo "Files converted. Do you want to merge them? (y/n)"
  read -s -n 1 reply
  if [[ "$reply" = "y" ]]; then
    ${MERGER} -S "${CONVERTED_DIR}" -O "${MERGED_MD5}"
  fi
fi

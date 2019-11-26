#!/usr/bin/env python3

import subprocess
import urllib.request
import json
import struct
from binascii import hexlify

def uint64_to_string(x):
  result, = struct.unpack('<Q', x)
  return ('0000000000000000' + hex(result).lstrip('0x'))[-16:]

def main():
  N = 10000
  testsetFilename = '../../../../pwned-lib/test/testset-{}-existent-collection1+2+3+4+5.md5'.format(N)
  webservice = subprocess.Popen([
    '../../pwned-server/pwned-server',
    '-I', testsetFilename,
    '-W', '16',
    '-T', '2',
    '-Q'
  ])
  rc = 0
  with open(testsetFilename, 'rb') as f:
    found = 0
    while True:
      upper = f.read(8)
      if not upper:
        break
      lower = f.read(8)
      hash = uint64_to_string(upper) + uint64_to_string(lower)
      count, = struct.unpack('<i', f.read(4))
      url_ctx = urllib.request.urlopen('http://localhost:31337/v1/pwned/api/lookup?hash=' + hash)
      response = url_ctx.read().decode('utf-8')
      url_ctx.close()
      data = None
      try:
        data = json.loads(response)
      except json.decoder.JSONDecodeError as err:
        print(err)
        rc = 1
        break
      else:
        if not isinstance(data['lookup-time-ms'], float):
          rc = 1
          break
        if not isinstance(data['found'], int):
          rc = 1
          break
        if not isinstance(data['hash'], str):
          rc = 1
          break
        if (data['hash'] == hash and data['found'] == count):
          found += 1
    if found != N:
      rc = 1

  webservice.kill()
  webservice.wait()
  return rc

if __name__ == '__main__':
  rc = main()
  exit(rc)

#!/usr/bin/env python3

from urllib.request import urlopen

def main():
  incert = False
  with urlopen('https://curl.haxx.se/ca/cacert.pem') as f:
    for l in f:
      line = l.decode('utf-8').strip()
      if incert:
        print('"' + line + '\\n"')
        if line.startswith('-----END CERTIFICATE-----'):
          incert = False
      elif line.startswith('-----BEGIN CERTIFICATE-----'):
        incert = True
        print('"' + line + '\\n"')

if __name__ == '__main__':
  main()

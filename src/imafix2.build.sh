#!/bin/bash
cd src
gcc -march=native -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -c libimaevm.c -o libimaevm.o
gcc -march=native -DHAVE_CONFIG_H -I. -I.. -include config.h  -g -O2 -Wall -Wstrict-prototypes -pipe -MT imafix2.d -MD -MP -c imafix2.c -o imafix2.o
gcc -march=native -g -O2 -Wall -pipe -lcrypto imafix2.o libimaevm.o -o imafix2
strip --strip-unneeded imafix2
echo "Completed compiling. imafix2"

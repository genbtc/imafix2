#!/bin/bash
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -MT evmctl.d -MD -MP -c evmctl.c -o evmctl.o
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -MT evmctl.d -MD -MP -c utils.c -o utils.o
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -c libimaevm.c -o libimaevm.o
gcc -march=znver3 -mshstk -g -O2 -Wall -pipe libimaevm.o evmctl.o utils.o -lcrypto -lkeyutils -o evmctl
strip --strip-unneeded evmctl
echo "Completed compiling. evmctl"
#/usr/lib/gcc/x86_64-pc-linux-gnu/14/../../../../x86_64-pc-linux-gnu/bin/ld: evmctl.o:/home/genr8eofl/src/imafix2/src/hash_info.h:23: multiple definition of `hash_algo_name'; libimaevm.o:/home/genr8eofl/src/imafix2/src/hash_info.h:23: first defined here

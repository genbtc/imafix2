#!/bin/bash
# -Wunused-variable -Wunused-function -Wmaybe-uninitialize
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -MD -c evmctl.c -o evmctl.o
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -MD -c utils.c -o utils.o
gcc -march=znver3 -mshstk -Wno-deprecated-declarations -DHAVE_CONFIG_H -I. -I.. -include config.h -g -O2 -Wall -Wstrict-prototypes -pipe -MD -c libimaevm.c -o libimaevm.o
gcc -march=znver3 -mshstk -g -O2 -Wall -pipe libimaevm.o evmctl.o utils.o -lcrypto -lkeyutils -o evmctl
strip --strip-unneeded evmctl
echo "Completed compiling. evmctl"

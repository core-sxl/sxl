Building SXL
================================================================

### Build Environment
It supports most Linux 64bit distros, such as Ubuntu 14.x/Ubuntu 16.x/Ubuntu 18.x/Cent OS 7.x.
Following prerequisite libraries/tools must be installed prior to the build process.

```code
# curl <remote-url-prepare_prerequisites.sh> |bash
```

### Build steps
Get the source code from SXL
Detailed steps

> you will find the core executable under the directory src/coind.

```code
# sh ./autogen-coin-man.sh coin
# make
```

### How to run the coind?
```code
# ./coind -datadir=. &
```
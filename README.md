# SymbolicSanitizer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**STILL IN DEVELOPMENT**

I'm really bad at naming so we probably will change it.
I don't have much time to code so progress will slowdown.

## Building

### Build Requirements

- Linux-amd64 (Tested on Ubuntu 20.04)
- [LLVM 12.0.1](http://llvm.org/docs/index.html) :

### Environment Variables

If installed from source,
append the following entries in the shell configuration file (`~/.bashrc`, `~/.zshrc`).

```
export PATH=/path-to-clang/bin:$PATH
export LD_LIBRARY_PATH=/path-to-clang/lib:$LD_LIBRARY_PATH
```

### Compilation

The build script will resolve most dependencies and setup the 
runtime environment.

```shell
make
make install
```

### Build in Docker

```
docker build -t symsan .
docker run  --rm --ulimit core=0 symsan bash -c 'cd /workdir/symsan && ./check.sh 2>/dev/null'
```


# Differential tests for Sparx-64/128

Contains tests to evaluate empirical probabilities of differentials and
boomerangs for Sparx-64/128.


## Getting Started

These instructions will get you a copy of the project up and running on your
local machine for development and testing purposes. See deployment for notes on
how to deploy the project on a live system.

Contains:

 * 'sparx-64-tests' Tests for the implementation of SPARX-64.
 * 'sparx-64-boomerang-test' 
   Evaluates probabilities of differentials and boomerangs for Sparx-64/128.


### Building:

 * 'cmake'
 * 'g++' or 'clang++' as compiler
 * 'pthreads' library, should be installable with the package manager on Linux
   distributions.


### Installation

If installed, you should be able to build with

```
cmake .
make
```

You can build all files on the level of the 'src' individually, e.g., :

```
make sparx-64-boomerang-test
```

The applications should be in 'bin/' and come with a short usage each. So,
after compilation, you should be able to run them, e.g.

```
bin/sparx-64-boomerang-test --num_keys 10 --alpha 0000000080008000 --delta 8000800080008000 --num_steps 3 --num_texts 1048576
```

You can clean the temporary files with 'clean.sh'.


## Running the tests

The project contains a few tests for the implementation of SPARX-64. Simply
compile 'make sparx-64-tests' and run


```
bin/sparx-64-tests
```

### Linting

Needs 

 * [CPPLint]('cpplint')
 * [PyLint]('pylint') 

You can use the script 'lint.sh' to lint the source code according to Google's
C++ style guide. By default, it generates in 'bin/linter' a report. You can
configure the style options in the file 'CPPLINT.cfg'.


### Profiling

Needs 

 * [Valgrind]('valgrind')

You can use the script 'profile.sh' with an executable and output options. It
will call valgrind and create a call-graph output for later analysis, e.g.,
with kcachegrind.


## License

See license.txt for details.


## Acknowledgments

* Uses the xorshift1024* implementation by Sebastiano Vigna (vigna@acm.org) 
  since it is faster than drawing from /dev/urandom.
* Uses the slim argument parser by Hilton Bristow.
  https://github.com/hbristow/argparse


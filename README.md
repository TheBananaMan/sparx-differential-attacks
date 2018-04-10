# sparx-differential-attacks
This is the git repository for the research paper "Differential Cryptanalysis of Round-Reduced Sparx-64/128", which will be presented at ACNS 2018. The full version of the paper is available on [ePrint](https://eprint.iacr.org/2018/332). If you use our tools/trails/results, it would be nice to cite our research paper :wink:

## Authors
- Ralph Ankele (<ralph.ankele.2015@live.rhul.ac.uk>)
- Eik List (<eik.list@uni-weimar.de>)

## Structure of the repository

### The differential models

The differential models for SPARX-64/128 can be found at `/code/differential models/sparxround.py`. We use [CryptoSMT](https://github.com/kste/cryptosmt) to search for differential trails and differentials. 

### Differential Trails/Differentials

The differential trails/differentials used in our attacks and many more can be found in `/results/sparx64_differentials/`.

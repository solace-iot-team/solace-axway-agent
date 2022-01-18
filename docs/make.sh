#!/usr/bin/env bash

make clean html
  code=$?; if [[ $code != 0 ]]; then echo ">>> XT_ERROR - $code make html"; exit 1; fi

make linkcheck
  code=$?; if [[ $code != 0 ]]; then echo ">>> XT_ERROR - $code make linkcheck"; exit 1; fi

###
# The End.

#!/bin/bash

rm -rf aclocal.m4 autom4te.cache depcomp missing test-driver config.sub config.guess install-sh ltmain.sh configure m4/*
for file in `find . | grep "\.in$"`; do
    rm "$file"
done

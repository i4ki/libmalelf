#!/bin/bash

echo "Generating AutoH3ll build files"

aclocal_bin=`which aclocal`
autoconf_bin=`which autoconf`
libtoolize_bin=`which libtoolize`
automake_bin=`which automake`
autoheader_bin=`which autoheader`

check_exec() {
    bin="$1"
    name="$2"

    if test "$bin" = ""; then
        echo "Program '$name' not found."
        exit 1
    fi
    echo "Running $bin"
    $bin

    if test "$?" != "0"; then
        echo "Error running $bin ($?)"
    fi
}

check_exec "$aclocal_bin" "aclocal"
check_exec "$autoconf_bin" "autoconf"
check_exec "$autoheader_bin" "autoheader"
check_exec "$libtoolize_bin" "libtoolize"
check_exec "$automake_bin --add-missing" "automake"

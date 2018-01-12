#!/bin/bash
#
# Copyright 2015-2018 Ping Identity Corporation
#
# Executes the Self-Service Account Manager application installer.  Run the
# script without any arguments to display the help, and refer to the
# documentation for additional information.
#

function die()
{
  echo $1
  exit 1
}

# Go into the script directory and export the SCRIPT_DIR, which is required by
# the installer.
cd `dirname $0`
export SCRIPT_DIR=`pwd -P`

# Make sure the war file is in the same directory as the script, and make sure
# that java is in the PATH.
[ -f "${SCRIPT_DIR}/ssam.war" ] || die "The ssam.war file must exist in ${SCRIPT_DIR}."
command -v java >/dev/null 2>&1 || die "Make sure that java is in the PATH."

# Run the installer or display the help if no arguments were provided.
if [ $# -eq 0 ]; then
  java -jar ssam.war install --help
else
  java -jar ssam.war install "$@"
fi

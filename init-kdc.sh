#!/bin/bash

# This file serves as a "first-and-the-only-boot" configuration
# file, because these commands cannot run during the image build
# phase in Dockerfile.

set -e

whoami

kdb5_util -r LOCAL destroy -f || touch /dev/null
kdb5_util create -r LOCAL -P password
kadmin.local -r LOCAL add_principal -pw password admin/admin@LOCAL
kadmin.local -r LOCAL add_principal -pw password user@LOCAL
kadmin.local -r LOCAL add_principal -pw password HTTP/localhost@LOCAL
kadmin.local -r LOCAL ktadd -k /tmp/keytab HTTP/localhost@LOCAL

kdb5_util -r LOCAL dump -verbose /tmp/dumpfile

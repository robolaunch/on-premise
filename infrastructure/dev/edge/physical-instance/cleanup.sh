#!/bin/bash

set -e;

BLUE='\033[0;34m';
GREEN='\033[0;32m';
RED='\033[0;31m';
NC='\033[0m';

TIMESTAMP=$(date +%s);
DIR_PATH=/root/robolaunch-cleanup-$TIMESTAMP;
mkdir -p $DIR_PATH;
OUTPUT_FILE="$DIR_PATH/out_cleanup_$TIMESTAMP.log";
touch $OUTPUT_FILE;

exec 3>&1 >$OUTPUT_FILE 2>&1;

print_global_log () {
    echo -e "${GREEN}$1${NC}" >&3;
}

print_log () {
    echo -e "${GREEN}$1${NC}";
}

print_err () {
    echo -e "${RED}Error: $1${NC}" >&3;
    exit 1;
}

opening () {
    apt-get update 2>/dev/null 1>/dev/null;
    apt-get install -y figlet 2>/dev/null 1>/dev/null;
    figlet 'robolaunch' -f slant;
}

check_if_root () {
    if [ $USER != "root" ]; then
        print_err "You should switch to root using \"sudo -i\" before setup."
    fi
}

cleanup () {
    k3s-uninstall.sh;
    rm -rf /root/robolaunch;
    rm -rf /root/run.sh;
    rm -rf /root/platform.yaml;
    rm -rf /var/openebs;
}

print_global_log "Preparing for the cleanup process...";
(check_if_root)

opening >&3

print_global_log "Cleaning up robolaunch ICP resources..";
(cleanup)

print_global_log "robolaunch ICP cleanup is successful.";

#!/usr/bin/env bash
#
set -e
set -u

usage() {
    echo "Usage: $0 major|minor|patch"
}

guess_current_version() {
    V=$(git tag -l | sed -e"s/v//" | grep -o ^[0-9][0-9]*.[0-9][0-9]*.[0-9][0-9]* | sort | tail -1 )
    if [ -z "$V" ]; then
        V=0.0.1
    fi
    if [[ ! "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$V is not a recognized version" 1>&2
        exit 1
    fi
    echo "$V"
}

get_major() {
    echo $1 | awk -F '.' '{ printf("%s", $1) }'
}

get_minor() {
    echo $1 | awk -F '.' '{ printf("%s", $2) }'
}

get_patch() {
    echo $1 | awk -F '.' '{ printf("%s", $3) }'
}

if [ $# -ne 1 ]; then
    usage && exit 1
fi

CURRENT_Mmp=$(guess_current_version)
CURRENT_M=$(get_major $CURRENT_Mmp)
CURRENT_m=$(get_minor $CURRENT_Mmp)
CURRENT_p=$(get_patch $CURRENT_Mmp)
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ $1 = "major" ]; then
    NEXT_M=$((($CURRENT_M+1)))
    RELEASE_Mmp=$NEXT_M.0.0
    RELEASE_BRANCH=branch/$NEXT_M.0
    NEXT_Mmp=$NEXT_M.0.1
elif [ $1 = "minor" ]; then
    NEXT_m=$((($CURRENT_m+1)))
    RELEASE_Mmp=$CURRENT_M.$NEXT_m.0
    RELEASE_BRANCH=branch/$CURRENT_M.$NEXT_m
    NEXT_Mmp=$CURRENT_M.$NEXT_m.1
elif [ $1 = "patch" ]; then
    NEXT_p=$(((CURRENT_p+1)))
    RELEASE_Mmp=$CURRENT_M.$CURRENT_m.$NEXT_p
    RELEASE_BRANCH=branch/$RELEASE_Mmp
    NEXT_Mmp=$CURRENT_M.$CURRENT_m.$NEXT_p
else
    usage && exit 1
fi

echo "Current branch: $CURRENT_BRANCH"
echo "Current version: $CURRENT_Mmp"
echo "Release version: $RELEASE_Mmp"

read -p "Press enter to continue"

git tag -a ${RELEASE_Mmp} -m "Release ${RELEASE_Mmp}"

echo
echo
read -p "Press enter to persist changes (push tag)"
git push origin ${RELEASE_Mmp}
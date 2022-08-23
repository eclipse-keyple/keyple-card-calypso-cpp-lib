#!/bin/sh

project_version=$1

if [ "$project_version" = "" ]; then
    echo "ERROR: project version is undefined"
    exit 1
fi

sed -i "s/%PROJECT_VERSION%/$project_version/g" ./.github/doxygen/Doxyfile

project_name="$(head -n 1 README.md | sed 's/#//')"

sed -i "s/%PROJECT_NAME%/$project_name/g" ./.github/doxygen/Doxyfile
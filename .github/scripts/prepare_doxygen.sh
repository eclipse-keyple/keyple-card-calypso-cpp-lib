#!/bin/sh

project_version=$1

project_name="$(head -n 1 README.md | sed 's/#//')"

repository_name=$(git rev-parse --show-toplevel | xargs basename)

echo "Clone $repository_name..."
git clone --branch doc https://github.com/eclipse/"$repository_name".git

cd "$repository_name" || exit

echo "Delete existing SNAPSHOT directory..."
rm -rf ./*-SNAPSHOT

echo "Create target directory $project_version..."
mkdir "$project_version"

echo "Copy Doxygen doc..."
cp -rf ../.github/doxygen/out/html/* "$project_version"/

echo "Update versions list..."
echo "| Version | Documents |" >list_versions.md
echo "|:---:|---|" >>list_versions.md
for directory in $(ls -rvd [0-9]*/ | sort -t. -k 1,1nr -k 2,2nr -k 3,3nr -k 4,4nr | cut -f1 -d'/'); do
  echo "| $directory | [API documentation]($directory) |" >>list_versions.md
done

echo "Computed all versions:"
cat list_versions.md

echo "Update project name to $project_name"
sed -i "2s/.*/title: $project_name/" _config.yml

cd ..

echo "Local docs update finished."




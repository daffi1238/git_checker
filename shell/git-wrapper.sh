# git_checker: `git clone` lo intercepta el shim ~/.local/bin/git (funciona en cualquier shell).
# Aquí solo un atajo para revisar un directorio ya clonado:  git-check <dir>
git-check() { git-safe-clone --scan "${1:-.}"; }

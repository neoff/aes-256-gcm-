cd $(dirname $0)

chmod +x pre-commit
chmod +x pre-commit-checkstyle

git config core.hooksPath config/githooks

current=$(go version | awk '{print $3}' | sed 's/^go//');

if [ "$(printf '%s\n' "1.24" "$current" | sort -V | head -n1)" != "1.24" ]; then
  echo "Go version != 1.24!";
  exit;
fi

go build ./...;
go vet ./...;

echo "run with: go run main.go";

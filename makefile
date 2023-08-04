ALL: build
	git add . && git commit -m "add new" && git push origin main
build:
	redoc-cli build openapi.yaml --options theme.json -o index.html

view: build
	open index.html

.PHONY: ALL build view
# terraform

## What is terraform

A utility to generate documentation from Terraform modules in various output formats.

Read the [User Guide](./docs/USER_GUIDE.md) and [Formats Guide](./docs/FORMATS_GUIDE.md) for detailed documentation.

## Installation

The latest version can be installed using `go get`:

``` bash
GO111MODULE="on" go get github.com/segmentio/terraform-docs@v0.9.1
```

If you are a Mac OS X user, you can use [Homebrew](https://brew.sh):

``` bash
brew install terraform-docs
```

Windows users can install using [Chocolatey](https://www.chocolatey.org):

``` bash
choco install terraform-docs
```

## Code Completion

The code completion for `bash` or `zsh` can be installed using:

**Note:** Shell auto-completion is not available for Windows users.

### bash

``` bash
terraform-docs completion bash > ~/.terraform-docs-completion
source ~/.terraform-docs-completion

# or simply the one-liner below
source <(terraform-docs completion bash)
```

### zsh

``` bash
terraform-docs completion zsh > /usr/local/share/zsh/site-functions/_terraform-docs
autoload -U compinit && compinit
```

To make this change permenant, the above commands can be added to your `~/.profile` file.

## Development Requirements

- [Go](https://golang.org/) 1.14 (ideally 1.13+)
- [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)
- [git-chlog](https://github.com/git-chglog/git-chglog)
- [golangci-lint](https://github.com/golangci/golangci-lint)




# generate go binary && create symlink
go install && sudo ln -sF ~/go/bin/dnscontrol /usr/local/bin/
go install golang.org/x/tools/cmd/stringer

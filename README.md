This is just a small stub to access libiptc-function from go code.

Test:
```
go test -c
sudo setcap cap_net_raw,cap_net_admin=eip go-iptables.test
./go-iptables.test
```

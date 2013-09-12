Test:
```
go test -c
sudo setcap cap_net_raw,cap_net_admin=eip go-iptables.test
./go-iptables.test
```

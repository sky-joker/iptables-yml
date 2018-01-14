# iptables-yml

[python-iptables](https://github.com/ldx/python-iptables)の勉強用に作ったツール

## 必要条件

* python3
* [python-iptables](https://github.com/ldx/python-iptables)
* [pyyaml](https://github.com/yaml/pyyaml)

## インストール

```bash
git clone https://github.com/sky-joker/iptables-yml.git
cd iptables-yml
yum -y install epel-release
yum -y install python34 python34-devel python34-pip gcc
pip3 install -r requirements.txt
chmod +x iptables-yml.py
```

## 使い方

```bash
# ./iptables-yml init -f example.yaml
# iptables -nL -v
Chain INPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0            /* Loopback Interface Rule */
   25  1720 ACCEPT     tcp  --  *      *       192.168.0.0/24       192.168.0.231        tcp dpt:22 /* SSH Rule */

Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 ACCEPT     all  --  *      lo      0.0.0.0/0            0.0.0.0/0            /* Loopback Interface Rule */
   14  2304 ACCEPT     tcp  --  *      *       192.168.0.231        192.168.0.0/24       tcp spt:22 /* SSH Rule */
```

## pyinstallerでonefile化

```bash
[root@localhost ~]# pyinstaller --onefile --add-binary /usr/lib64/python3.4/site-packages/libxtwrapper.cpython-34m.so:. iptables-yml.py
```

## ライセンス

[MIT](https://github.com/sky-joker/iptables-yml/blob/master/LICENSE.txt)

## 作者

[sky-joker](https://github.com/sky-joker)

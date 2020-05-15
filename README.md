Run VM:
```
$ vagrant up
```

Run HTTP service:
```
$ vagrant ssh
$ cd /vagrant/
$ sudo go run server.go
```

Authenticate client and invoke HTTP request:
```
$ vagrant ssh
Last login: Fri May 15 09:05:25 2020 from 10.0.2.2
$ echo password | kinit user@LOCAL
Password for user@LOCAL:
$ curl -v --negotiate -u user:password localhost:9000
```

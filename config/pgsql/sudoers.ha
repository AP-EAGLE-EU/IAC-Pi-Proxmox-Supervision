postgres ALL=(ALL) NOPASSWD: ALL
postgres ALL=(ALL) NOPASSWD: /bin/systemctl start postgresql.service
postgres ALL=(ALL) NOPASSWD: /bin/systemctl stop postgresql.service
postgres ALL=(ALL) NOPASSWD: /bin/systemctl restart postgresql.service
postgres ALL=(ALL) NOPASSWD: /bin/systemctl reload postgresql.service
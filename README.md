### Asus-Merlin-Wireguard
 
# WG-TOOL.SH

Wg-tool.sh is a “wg-quick (8)” replacement tool for Asus-Merlin firmware based routers that support the Wireguard user space tool.  The script does not require Entware to be installed or a USB drive to be used.
I built this script in part as over the last couple of years I have helped a couple folks get Wireguard working on their routers who either did not have a USB drive (XT12) or did not want to install Entware.
The script can be placed in the /jffs drive in a convenient location.  I recommend placing the script in /jffs/addons/wireguard. 

# Installation

`curl --retry 3 https://raw.githubusercontent.com/Bandsaw12/Asus-Merlin-Wireguard/main/wg-tool.sh`

# Overview

The script has all the functionality of the official wg-quick script written in bash with a couple of exceptions.  The script does not support the SaveConfig directive.  The directive is read, and processed in order to remain compatible with existing Wireguard config files, but the directive is not acted on.  Secondly, the script goes one step further and adds appropriate fire wall rules depending on if the config file is a server configuration or a client configuration.
The script looks for a config file in the same directory in which the script is located.  If the script cannot find a config file there, it will look in the directory “/jffs/addons/wireguard”

# To use the script,

`Wg-tool.sh [ start | stop | restart] [interface_name ] {show}`

Where a configuration file named “{interface_name}.conf” exists either in the same directory as wg-tool.sh or in “/jffs/addons/wireguard”.
The optional argument show can be added which will have the script print out key commands that are being carried out by the script.

# Firewall-start and nat-start scripts

Since firewall and NAT restarts will clear any custom firewall rules, wg-tool.sh can be placed in both the firewall-start and nat-start scripts with the following options which will loop through all running wireguard interfaces and re-add the appropriate rules;

`Wg-tool.sh firewall {show}`			Placed in the firewall-start script

`Wg-tool.sh nat {show}`								Placed in the nat-start script

# IPv6 handling

I have done my best to code in the required commands and firewall rules for systems running IPv6.  However, I do not have IPv6 at home and as I am behind a CGNAT, I cannot get any kind of IPv6 tunnel broker to work.  Therefore, I fully expect that there will be problems with IPv6 installations.  I apologize in advance.

# Notes

1.	The script uses the same default routes mythology as is described in the official wireguard documentation (https://www.wireguard.com/netns/) as described under the “Improved Rule Based Routing” section.  In my tests, I found that using the traditional overwriting of the default route would get wiped out anytime the wan interface went down or reset.  Whereas the default route method used by the script seemed to stay in place even when the wan was reset or dropped.  This may be advantageous if your aim is not to leak and data over the wan.  For more information, you can also see this site for more information: https://www.procustodibus.com/blog/2022/01/wg-quick-firewall-rules/

2.	The “Table” directive in a config file is handled the same as in wg-quick.  If set to Off,  no routing rules are added at all.  If set to a number, a IPSET table is added by the number provided, but any other IPSET, routing or policy rules will have to be set up via the Pre/Post Up/Down directive.  Just as in the official wg-quick script.  My intentions with this script were to keep things simple and convenient for those who do not have a USB port or do not want Entware and who are primarily still using an AC router.  If you want rule based routing, check out SNBForum user @Marineau fantastic script “Wireguard Session Manager”.  More info here: https://www.snbforums.com/threads/session-manager-4th-thread.81187/post-793726

3.	If the DNS directive is used in the config file, DNS redirection is handled through iptable rules and not by altering DNSmasq.  Only port 53 is redirected at the moment.

4.	I don’t expect that there will be much demand for this script, but if anyone wants to improve or make fixes where IPv6 is concerned, I will create a develop branch in GitHub where pull requests can be made.

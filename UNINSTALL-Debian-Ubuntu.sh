#! /bin/sh
#
# ipv6mon un-installation script for Debian GNU/Linux and Ubuntu systems
#
# Copyright (C) 2011-2012 Fernando Gont
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
###############################################################################

	if ! uname -a | grep -e debian -e Ubuntu >/dev/null 2>&1; then
		echo "This uninstaller script should be used only with Debian GNU/Linux or Ubuntu"
		exit 1
	fi

	if [ `id -u` -ne 0 ]; then
		echo "Must have superuser privileges to uninstall ipv6mon" && exit 1
	fi

	echo "Uninstalling ipv6mon from the local system"

	echo -n "Stoping ipv6mon..."

	if /etc/init.d/ipv6mon stop >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "not running."
	fi

	echo -n "Removing ipv6mon from /etc/init.d..."

	if rm /etc/init.d/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Removing ipv6mon from /usr/sbin/..."

	if rm /usr/sbin/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Removing symlinks from /etc/rc.d/*..."

	if update-rc.d ipv6mon remove >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Removing user:group ipv6mon:ipv6mon from the system..."

	if userdel ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Removing manual pages from the local system..."

	if test -d "/usr/share/man/man8" && test -d "/usr/share/man/man5" >/dev/null 2>&1; then
		rm "/usr/share/man/man8/ipv6mon.8.gz" 2>&1
		rm "/usr/share/man/man5/ipv6mon.conf.5.gz" 2>&1

		echo "succeeded."
	else
		echo "failed."
		echo "You must manually remove the manual pages from your system!"
	fi

	if test -f /etc/logrotate.d/ipv6mon 2>&1; then
		echo -n "Removing ipv6mon from /etc/logrotate.d/..."

		if rm /etc/logrotate.d/ipv6mon >/dev/null 2>&1; then
			echo "succeeded."
		else
			echo "failed." && exit 1
		fi
	fi

	echo "Note: Configuration file /etc/ipv6mon.conf has NOT been removed."

	echo "ipv6mon has been successfully uninstalled from the system!"

	exit 0


#! /bin/sh
#
# ipv6mon installation script for Debian GNU/Linux and Ubuntu systems
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
		echo "Must have superuser privileges to install ipv6mon" && exit 1
	fi

	echo "Installing ipv6mon on the local system"

	echo -n "Compiling ipv6mon..."

	if gcc ipv6mon.c -Wall -lpcap -o ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Adding user:group ipv6mon:ipv6mon to the system..."

	if useradd -U -M -d /nonexistent -s /usr/sbin/nologin ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting owner of ipv6mon to root:root..."

	if chown root:root ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting file mode bits of ipv6mon..."

	if chmod 0755 ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Copying ipv6mon to /usr/sbin/..."

	if cp ipv6mon /usr/sbin/ >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	if test -f /etc/ipv6mon.conf; then
		echo -n "Renaming old /etc/ipv6mon.conf to /etc/ipv6mon.conf.old..."

		if mv /etc/ipv6mon.conf /etc/ipv6mon.conf.old >/dev/null 2>&1; then
			echo "succeeded."
		else
			echo "failed." && exit 1
		fi
	fi

	echo -n "Setting owner of ipv6mon.conf to root:root..."

	if chown root:root ipv6mon.conf >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting file mode bits of ipv6mon.conf..."

	if chmod 0644 ipv6mon.conf >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Copying ipv6mon.conf to /etc/..."

	if cp ipv6mon.conf /etc/ >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting owner of Debian-Ubuntu/init.d/ipv6mon to root:root..."

	if chown root:root Debian-Ubuntu/init.d/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting file mode bits of Debian-Ubuntu/init.d/ipv6mon..."

	if chmod 0755 Debian-Ubuntu/init.d/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Copying init.d/ipv6mon to /etc/init.d..."

	if cp Debian-Ubuntu/init.d/ipv6mon /etc/init.d/ >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Adding symlinks to /etc/rc.d/*..."

	if update-rc.d ipv6mon defaults >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Copying manual pages to the local system..."

	if test -d "/usr/share/man/man8" && test -d "/usr/share/man/man5" >/dev/null 2>&1; then
		chown root:root "manuals/ipv6mon.8" 2>&1
		chmod 0644 "manuals/ipv6mon.8" >/dev/null 2>&1
		cp manuals/ipv6mon.8 "/usr/share/man/man8/" 2>&1
		gzip "/usr/share/man/man8/ipv6mon.8" 2>&1

		chown root:root "manuals/ipv6mon.conf.5" 2>&1
		chmod 0644 "manuals/ipv6mon.conf.5" >/dev/null 2>&1
		cp "manuals/ipv6mon.conf.5" "/usr/share/man/man5/" 2>&1
		gzip "/usr/share/man/man5/ipv6mon.conf.5" 2>&1

		echo "succeeded."
	else
		echo "failed."
		echo "You must install the manual pages on your system manually!"
	fi

	echo -n "Checking whether /etc/logrotate.d/ exists..."

	if test -d /etc/logrotate.d >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed."
		echo "Must configure log rotatation manually!"
		echo "ipv6mon installation complete!"
		exit 1
	fi

	echo -n "Setting owner of /etc/logrotate.d/ipv6mon to root:root..."

	if chown root:root Debian-Ubuntu/logrotate.d/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Setting file mode bits of Debian-Ubuntu/logrotate.d/ipv6mon..."

	if chmod 0644 Debian-Ubuntu/logrotate.d/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo -n "Copying Debian-Ubuntu/logrotate.d/ipv6mon to /etc/logrotate.d..."

	if cp Debian-Ubuntu/logrotate.d/ipv6mon /etc/logrotate.d/ >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	echo "ipv6mon installation complete!"
	exit 0


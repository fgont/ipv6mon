#! /bin/sh
#
# ipv6mon installation script for Mac OS X
#  Adapted from the Debian/Ubuntu Installation script by
#  Yvan Janssens (yvan.janssens@vasco.com)
#
# Copyright (C) 2011 United Kingdom's Centre for the Protection of 
#                    National Infrastructure (UK CPNI)
# 
# Programmed by Fernando Gont on behalf of CPNI (http://www.cpni.gov.uk)
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

	if ! uname -a | grep Darwin >/dev/null 2>&1; then
		echo "This installer script should be used only with Mac OS X."
		exit 1
	fi

	if [ `id -u` -ne 0 ]; then
		echo "Must have superuser privileges to install ipv6mon"
		echo "hint: sudo ./INSTALL-MacOSX.sh"
		exit 1
	fi

	echo "Installing ipv6mon on the local system"

	printf  "Compiling ipv6mon..."

	if gcc ipv6mon.c -Wall -lpcap -o ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi


	printf  "Setting owner of ipv6mon to root:wheel..."

	if chown root:wheel ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Setting file mode bits of ipv6mon..."

	if chmod 0755 ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Copying ipv6mon to /usr/sbin/..."

	if cp ipv6mon /usr/sbin/ >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	if test -f /etc/ipv6mon.conf; then
		printf  "Renaming old /etc/ipv6mon.conf to /etc/ipv6mon.conf.old..."

		if mv /etc/ipv6mon.conf /etc/ipv6mon.conf.old >/dev/null 2>&1; then
			echo "succeeded."
		else
			echo "failed." && exit 1
		fi
	fi

	printf  "Setting owner of ipv6mon.conf to root:wheel..."

	if chown root:wheel ipv6mon.conf >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Setting file mode bits of ipv6mon.conf..."

	if chmod 0644 ipv6mon.conf >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Copying ipv6mon.conf to /etc/..."

	if cp ipv6mon_osx.conf /etc/ipv6mon.conf >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Copying ipv6mon StartupItem to /Library/StartupItems..."
	
	if cp -R MacOSX/ipv6mon /Library/StartupItems >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi

	printf  "Fixing up ipv6mon StartupItem permissions..."

	if chown -R root:wheel /Library/StartupItems/ipv6mon >/dev/null 2>&1; then
		echo "succeeded."
	else
		echo "failed." && exit 1
	fi


	printf  "Copying manual pages to the local system..."

	if test -d "/usr/share/man/man8" && test -d "/usr/share/man/man5" >/dev/null 2>&1; then
		chown root:wheel "manuals/ipv6mon.8" 2>&1
		chmod 0644 "manuals/ipv6mon.8" >/dev/null 2>&1
		cp manuals/ipv6mon.8 "/usr/share/man/man8/" 2>&1
		gzip "/usr/share/man/man8/ipv6mon.8" 2>&1

		chown root:wheel "manuals/ipv6mon.conf.5" 2>&1
		chmod 0644 "manuals/ipv6mon.conf.5" >/dev/null 2>&1
		cp "manuals/ipv6mon.conf.5" "/usr/share/man/man5/" 2>&1
		gzip "/usr/share/man/man5/ipv6mon.conf.5" 2>&1

		echo "succeeded."
	else
		echo "failed."
		echo "You must install the manual pages on your system manually!"
	fi

	echo "ipv6mon installation complete!"
	exit 0


#!/bin/bash

pushd () {
    command pushd "$@" > /dev/null
}

popd () {
    command popd "$@" > /dev/null
}

exit () {
	popd
	popd
	command exit "$@"
}

install_sgx_driver () {
	
	sudo apt-get install linux-headers-$(uname -r)
	
	pushd linux-sgx-driver
	
	make
	sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
	sudo cp isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
	sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
	sudo /sbin/depmod
	sudo /sbin/modprobe isgx
	
	popd
	
}

uninstall_sgx_driver () {
	
	pushd linux-sgx-driver
	
	sudo service aesmd stop
	sudo /sbin/modprobe -r isgx
	sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
	sudo /sbin/depmod
	sudo /bin/sed -i '/^isgx$/d' /etc/modules
	
	popd
	
}

is_sgx_driver_installed () {
	if [ -f "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx/isgx.ko" ]; then
		return 1
	else
		return 0
	fi
}

pushd libs
pushd Intel_SGX

is_uninstall=false

for in_option in "$@"
do
	if [ "$in_option" == "--uninstall" ] || [ "$in_option" == "-u" ]; then
		is_uninstall=true
	fi
done

is_sgx_driver_installed
is_driver_installed=$?

if [ "$is_driver_installed" = 1 ] && [ "$is_uninstall" = false ]; then
	echo "SGX Driver is already installed!"
	exit 0
elif [ "$is_driver_installed" = 0 ] && [ "$is_uninstall" = true ]; then
	echo "SGX Driver had not installed yet!"
	exit 1
elif [ "$is_driver_installed" = 0 ] && [ "$is_uninstall" = false ]; then
	echo "Install SGX Driver..."
	install_sgx_driver
	echo "SGX Driver Installation finished!"
elif [ "$is_driver_installed" = 1 ] && [ "$is_uninstall" = true ]; then
	echo "Uninstall SGX Driver..."
	uninstall_sgx_driver
	echo "SGX Driver Un-installation finished!"
fi

exit 0

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

build_psw () {
	pushd linux-sgx

	sudo apt-get install libssl-dev libcurl4-openssl-dev

	pushd psw

	make DEBUG=1

	popd

	make psw_install_pkg DEBUG=1
	
	popd
}

install_psw () {
	sudo $@ #--prefix=/opt/intel/
}

find_sdk_bin () {
	for file in ./linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin; do
		bin_file_path="$file"
	done
	echo $bin_file_path
}

find_psw_bin () {
	for file in ./linux-sgx/linux/installer/bin/sgx_linux_x64_psw_*.bin; do
		bin_file_path="$file"
	done
	echo $bin_file_path
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

is_sgx_psw_installed=false
is_sgx_psw_built=false

INSTALL_PATH=/opt/intel/sgxpsw
if [ -d "$INSTALL_PATH" ]; then
	is_sgx_psw_installed=true
	if [ "$is_uninstall" = false ]; then
		echo "SGX PSW already installed in $INSTALL_PATH!"
		exit 0
	fi
fi

if [ "$is_uninstall" = true ]; then
	if [ "$is_sgx_psw_installed" = true ]; then
		echo "Uninstall SGX PSW..."
		sudo $INSTALL_PATH/uninstall.sh
		echo "SGX PSW Un-installation finished!"
		exit 0
	else
		echo "SGX PSW had not installed!"
		exit 1
	fi
fi

echo "Install SGX PSW..."

sdk_bin_file_path=$( find_sdk_bin )

if [ -f "$sdk_bin_file_path" ]; then 
	is_sgx_sdk_built=true
	echo "Found SDK bin file: $bin_file_path."
fi

bin_file_path=$( find_psw_bin )

if [ -f "$bin_file_path" ]; then 
	chmod +x $bin_file_path
	is_sgx_psw_built=true
	echo "Found PSW bin file: $bin_file_path."
fi

if [ "$is_sgx_sdk_built" = false ]; then
	echo "SGX SDK should be built before PSW!"
	exit 1
elif [ "$is_sgx_psw_built" = false ]; then
	build_psw
	
	bin_file_path=$( find_psw_bin )
	
	if [ -f "$bin_file_path" ]; then 
		chmod +x $bin_file_path
		is_sgx_psw_built=true
		echo "Found SDK bin file: $bin_file_path."
	else
		echo "SGX SDK is not built correctly!"
		exit 1
	fi
fi

install_psw "$bin_file_path"

echo "SGX PSW Installation finished!"

exit 0

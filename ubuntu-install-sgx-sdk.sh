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

set_sgx_env_var () {
	if [ -z "$SGX_SDK" ]; then
		echo "Setting environment variable..."
		echo "export SGX_SDK=/opt/intel/sgxsdk">>~/.bashrc
		echo "export SGX_SDK=/opt/intel/sgxsdk">>~/.profile
		export SGX_SDK=/opt/intel/sgxsdk
	fi
}

build_sdk () {
	pushd linux-sgx

	sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev
	./download_prebuilt.sh

	pushd sdk

	make USE_OPT_LIBS=0 DEBUG=1

	popd

	make sdk_install_pkg DEBUG=1
	
	popd
}

install_sdk () {
	sudo $@ --prefix=/opt/intel/
}

find_sdk_bin () {
	for file in ./linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin; do
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

set_sgx_env_var

is_sgx_sdk_installed=false
is_sgx_sdk_built=false

if [ -d "$SGX_SDK" ] && [ "$(ls -A $SGX_SDK)" ]; then
	if [ -f "$SGX_SDK/uninstall.sh" ]; then
		is_sgx_sdk_installed=true
		if [ "$is_uninstall" = false ]; then
			echo "SGX SDK is already installed!"
			exit 0
		fi
	else
		echo "SGX SDK is not installed correctly!"
		exit 1
	fi
fi

if [ "$is_uninstall" = true ]; then
	if [ "$is_sgx_sdk_installed" = true ]; then
		echo "Uninstall SGX SDK..."
		sudo $SGX_SDK/uninstall.sh
		echo "SGX SDK Un-installation finished!"
		exit 0
	else
		echo "SGX SDK had not installed!"
		exit 1
	fi
fi

echo "Install SGX SDK..."

bin_file_path=$( find_sdk_bin )

if [ -f "$bin_file_path" ]; then 
	chmod +x $bin_file_path
	is_sgx_sdk_built=true
	echo "Found SDK bin file: $bin_file_path."
fi

if [ "$is_sgx_sdk_built" = false ]; then
	build_sdk
	
	bin_file_path=$( find_sdk_bin )
	
	if [ -f "$bin_file_path" ]; then 
		chmod +x $bin_file_path
		is_sgx_sdk_built=true
		echo "Found SDK bin file: $bin_file_path."
	else
		echo "SGX SDK is not built correctly!"
		exit 1
	fi
fi

install_sdk "$bin_file_path"

echo "SGX SDK Installation finished!"

exit 0

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

set_sgx_env_var_init () {
	if [ -z "$SGX_SDK" ]; then
		export SGX_SDK_TEMP=/opt/intel/sgxsdk
	else
		export SGX_SDK_TEMP="$SGX_SDK"
	fi
}

set_sgx_env_var_final () {
	if [ -z "$SGX_SDK" ]; then
		echo "Setting environment variable..."
		echo "source $SGX_SDK_TEMP/environment">>~/.bashrc
		echo "source $SGX_SDK_TEMP/environment">>~/.profile
		source $SGX_SDK_TEMP/environment
	fi
}

unset_sgx_env_var () {
	sed -i "/^source ..*sgxsdk\/environment$/d" ~/.bashrc
	sed -i "/^source ..*sgxsdk\/environment$/d" ~/.profile
}

build_sdk () {
	pushd linux-sgx

	sudo apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python libssl-dev
	./download_prebuilt.sh

	pushd sdk

	make DEBUG=1 #USE_OPT_LIBS=0

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

set_sgx_env_var_init

is_sgx_sdk_installed=false
is_sgx_sdk_built=false

if [ -d "$SGX_SDK_TEMP" ] && [ "$(ls -A $SGX_SDK_TEMP)" ]; then
	if [ -f "$SGX_SDK_TEMP/uninstall.sh" ]; then
		is_sgx_sdk_installed=true
		if [ "$is_uninstall" = false ]; then
			set_sgx_env_var_final
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
		sudo $SGX_SDK_TEMP/uninstall.sh
		unset_sgx_env_var
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

set_sgx_env_var_final

echo "SGX SDK Installation finished!"

exit 0

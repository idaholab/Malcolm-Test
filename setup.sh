#!/bin/bash

PWD=$(pwd)
USER=$(whoami)

sudo apt-get update &>/dev/null

is_package_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

packages=(
    vagrant
    ansible
    sshpass
    wget
    jq
)

# required to resync folder to rerun tests on already running vm
sudo vagrant plugin install vagrant-rsync-back

# install dependency list
for package in "${packages[@]}"; do
    if is_package_installed "$package"; then
        echo "$package is already installed."
    else
        echo "Installing $package..."
        sudo apt-get -y install "$package" &>/dev/null
    fi
done

echo "Which VM provider do you want to use with Vagrant and install? Note: Virtualbox is the fastest and most stable"
echo "1. VirtualBox"
echo "2. VMware"
echo "3. libvirt"
read -p "Enter your choice (1-3): " choice
echo ""

case $choice in
    1)
        # Check if VirtualBox is installed
        if ! command -v VBoxManage &> /dev/null
        then
            echo "installing Virtualbox..."
            sudo apt-get install -y virtualbox
        fi
        ;;
    2)
        # Check if VMware is installed
        if ! command -v vmrun &> /dev/null
        then
            echo "You will need to install vmware manually from the Broadcom site https://knowledge.broadcom.com/external/article/368667/download-and-license-information-for-vmw.html" 
            sudo apt-get -y install open-vm-tools  
        fi

        # install vmware-vagrant utility
        if dpkg-query -W vagrant-vmware-utility &> /dev/null
        then
            echo "vagrant-vmware-utility package is installed."
        else
            echo "vagrant-vmware-utility package is not installed, installing..."
            wget https://releases.hashicorp.com/vagrant-vmware-utility/1.0.21/vagrant-vmware-utility_1.0.21_x86_64.deb
            sudo apt install $PWD/vagrant-vmware-utility_1.0.21_x86_64.deb
            rm $PWD/vagrant-vmware-utility_1.0.21_x86_64.deb
            sudo systemctl start vagrant-vmware-utility
        fi

        # Install necessary Vagrant plugins for VMware
        if vagrant plugin list | grep -q vagrant-vmware-desktop
        then
            echo "vmware plugin is already installed"
        else
            echo "installing plugin"
            vagrant plugin install vagrant-vmware-desktop
        fi

        if ! command -v net-tools &>/dev/null 
        then 
            sudo apt-get install -y net-tools
        fi

        exit 1
        ;;
    3)
        # libvirt
        if ! command -v virsh &> /dev/null
        then
            echo "libvirt is not installed, installing..."
            sudo apt-get install -y qemu libvirt-daemon-system ebtables libguestfs-tools ruby-fog-libvirt libvirt-dev libvirt-daemon libvirt-clients virt-manager python3-libvirt
        fi

        if vagrant plugin list | grep -q vagrant-libvirt
        then
            echo "vagrant-libvirt plugin is already installed."
        else
            echo "Installing vagrant-libvirt plugin..."
            vagrant plugin install vagrant-libvirt
        fi
        ;;
    *)
        echo "Invalid choice. Please enter a valid option."
        exit 1
        ;;
esac

echo "Setup complete for the selected VM provider, ready to run CompleteTest.sh."
echo ""
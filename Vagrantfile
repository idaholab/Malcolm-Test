
Vagrant.configure("2") do |config|

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine and only allow access
  # via 127.0.0.1 to disable public access
  # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  config.vm.box = "bento/ubuntu-22.04"
  config.vm.box_version = "202309.08.0"
  config.vm.disk :disk, size: "150GB", primary: true
  config.vm.hostname = "Malcolm"
  config.vm.define "Malcolm"
  config.vm.box_download_insecure = true

  # config.vm.synced_folder ".", "/vagrant", type: "nfs", mount_options: ["vers=3,tcp"]

  ## If using Virtualbox Provider, you will access Malcolm VM Web interaface on https://localhost:8080
  config.ssh.insert_key = false

  config.vm.network "private_network", type: "dhcp"
  config.vm.network "forwarded_port", guest: 443, host: 8080, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |v|
    virtualbox = 1
    v.name = "Malcolm"
    # vb.customize ["modifyvm", :id, "--cpuexecutioncap", "80"]  
    v.memory = 32000
    v.cpus = 6
    v.customize ["modifyvm", :id, "--ioapic", "on"]

    v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    v.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
  end
  
  ## From the vagrant docs for determining a VM provider.
  # 1. The --provider flag on a vagrant up is chosen above all else, if it is present.
  # 2. If the VAGRANT_DEFAULT_PROVIDER environmental variable is set, it takes next priority and will be the provider chosen.
  # 3. Vagrant will go through all of the config.vm.provider calls in the Vagrantfile and try each in order. It will choose the first provider that is usable. For example, if you configure Hyper-V, it will never be chosen on Mac this way. It must be both configured and usable.

  # NAT is not working for vmware-desktop at the moment
  config.vm.provider "vmware_desktop" do |desktop, override|    
    override.vm.box = "generic/ubuntu2004"
    desktop.force_vmware_license = "workstation"
    desktop.vmx["memsize"] = "32000"
    desktop.vmx["numvcpus"] = "6" 
    desktop.gui = true
    desktop.port_forward_network_pause = 5
  end
  
  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 32000
    libvirt.cpus = 6
  end

  #set everything else up with ansible
  config.vm.provision "ansible" do |ansible|
    # ansible.verbose = "v"   
    ansible.playbook = "playbook.yml"
    ansible.compatibility_mode = "2.0"
  end

end

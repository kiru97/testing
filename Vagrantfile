# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-18.04"

  config.vm.define "pi" do |pi|
    pi.vm.hostname = "pi"
    pi.vm.network "private_network", ip: "192.168.2.254", virtualbox__intnet: "client1", nic_type: "virtio"
    pi.vm.network "private_network", ip: "192.168.2.253", virtualbox__intnet: "client2", nic_type: "virtio"
    pi.vm.network "private_network", ip: "192.168.2.252", virtualbox__intnet: "client3", nic_type: "virtio"
    pi.vm.synced_folder "..", "/home/vagrant/go/src/gitlab.ti.bfh.ch/glab",
      owner: "vagrant", group: "vagrant"
    pi.vm.provision "shell", inline: <<-SHELL
      apt-get install -y gcc
      chown -R vagrant /home/vagrant
      ln -s /home/vagrant/go/src/gitlab.ti.bfh.ch/glab /home/amalathask/Repositories/skeleton
    SHELL
  end

  config.vm.define "client1" do |client1|
    client1.vm.hostname = "client1"
    client1.vm.network "private_network", ip: "192.168.2.2", virtualbox__intnet: "client1", nic_type: "virtio"
  end

  config.vm.define "client2" do |client2|
    client2.vm.hostname = "client2"
    client2.vm.network "private_network", ip: "192.168.2.3", virtualbox__intnet: "client2", nic_type: "virtio"
  end

  config.vm.define "client3" do |client3|
    client3.vm.hostname = "client3"
    client3.vm.network "private_network", ip: "192.168.2.4", virtualbox__intnet: "client3", nic_type: "virtio"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
  SHELL

  config.vm.provider "virtualbox" do |virtualbox|
      # https://github.com/hashicorp/vagrant/issues/7741
      # Use virtio because VLAN tags are stripped with the default adapter
      virtualbox.customize ["modifyvm", :id, "--nictype1", "virtio"]
      virtualbox.customize ["modifyvm", :id, "--nicpromisc2", "allow-all"]
      virtualbox.customize ["modifyvm", :id, "--nicpromisc3", "allow-all"]
      virtualbox.customize ["modifyvm", :id, "--nicpromisc4", "allow-all"]
  end
end

# -*- mode: ruby -*-
# vi: set ft=ruby :

$script = <<-'SCRIPT'

# This is for development, feel free to comment out
rpm --import https://packages.microsoft.com/keys/microsoft.asc
sh -c 'echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo'

# Install necessary packages
dnf -y install krb5-workstation krb5-server krb5-devel golang tmux code

# Init KDC
bash /vagrant/init-kdc.sh

# Copy configuration files
cp /vagrant/kdc.conf /var/kerberos/krb5kdc/kdc.conf
cp /vagrant/krb5.conf /etc/krb5.conf

# Run the KDC service
systemctl enable --now krb5kdc
systemctl status krb5kdc

SCRIPT

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/31-cloud-base"
  config.vm.network "private_network", ip: "127.0.0.10"

  # Increase amount of memory to handle dnf transactions
  # Add your provider here, e.g. libvirt
  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = 4096
    vb.cpus = 2
  end

  config.vm.provision "shell", inline: $script
end

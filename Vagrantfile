# -*- mode: ruby -*-
# vi: set ft=ruby :

$install = <<EOF
PRE=$(date +%s)
MY_NAME=vagrant
MY_HOME=/home/${MY_NAME}
export DEBIAN_FRONTEND=noninteractive

# Use DK archives
sudo perl -pi -e 's/us.archive/dk.archive/g' /etc/apt/sources.list

# Install packages
sudo -E apt-get -y update
sudo apt-get install -y software-properties-common 
sudo apt-add-repository -y ppa:brightbox/ruby-ng
sudo -E apt-get -y update
sudo -E apt-get -y upgrade
sudo -E apt-get -y install git python-pip python-dev build-essential    \
    python-software-properties gdb curl vim exuberant-ctags pyflakes    \
    cmake realpath tmux source-highlight libpq5 gcc-multilib libc6-i386 \
    libc6-dev-i386 qemu-user-static libreadline-dev libssl-dev libpq-dev\
    nmap libreadline5 ruby2.2 libsqlite3-dev libpcap-dev openjdk-7-jre  \
    autoconf postgresql nasm pgadmin3 zlib1g-dev libxml2-dev            \
    libxslt1-dev ruby2.2-dev screen
sudo update-alternatives --set ruby /usr/bin/ruby2.2

# Init .repositories
mkdir .repositories
function git_clone(){
    base=$(basename "${1}" | sed 's/\.git//g')
    if test -n "${3}"; then
        git clone -b "${3}" "${1}" ${MY_HOME}/.repositories/"${base}"
    else
        git clone "${1}" ${MY_HOME}/.repositories/"${base}"
    fi
    if test -n "${2}"; then
        ln -s ${MY_HOME}/.repositories/"${base}" "${2}"/"${base}"
    fi
}

# Get workstation setup
git_clone https://github.com/RobertLarsen/WorkstationSetup.git

# Install Vim
HOME=$MY_HOME USER=$MY_NAME bash .repositories/WorkstationSetup/vim.sh

# Install pwntools + dependencies
git_clone https://github.com/Gallopsled/pwntools.git ${MY_HOME}
cd pwntools
sudo sed -i 's/kernel.yama.ptrace_scope = 1/kernel.yama.ptrace_scope = 0/' /etc/sysctl.d/10-ptrace.conf
sudo service procps restart
sudo sed -i "s/\['splitw'\]/\['splitw', '-h'\]/" pwnlib/util/misc.py
sudo pip2 install -r requirements.txt
sudo python setup.py install
cd ${MY_HOME}

# Install many binutils
sudo apt-add-repository --yes ppa:pwntools/binutils
sudo apt-get update
sudo apt-get install binutils-{arm,i386,mips}-linux-gnu

# Enable core dumps
ulimit -c 100000
echo 'vagrant     soft      core      unlimited' | sudo tee /etc/security/limits.conf

# Create .gdbinit
echo 'set follow-fork-mode child'          >> /home/vagrant/.gdbinit
echo 'set disassembly-flavor intel'        >> /home/vagrant/.gdbinit
echo 'set auto-load safe-path /'           >> /home/vagrant/.gdbinit
echo 'set disable-randomization off'       >> /home/vagrant/.gdbinit

# Install peda
git_clone https://github.com/zachriggle/peda.git
echo '#source ~/.repositories/peda/peda.py' >> /home/vagrant/.gdbinit

# Install Metasploit
sudo gem2.2 install bundler
git_clone https://github.com/rapid7/metasploit-framework.git
cd $HOME/.repositories/metasploit-framework
bundle install
sudo chmod -R a+r /var/lib/gems/2.2.0/gems
echo 'export PATH=$PATH:$HOME/.repositories/metasploit-framework' >> $HOME/.bashrc

# Update .bashrc
echo 'export EDITOR=vim'                        >> $HOME/.bashrc
echo 'function pwn(){'                          >> $HOME/.bashrc
echo '    fname="exploit.py"'                   >> $HOME/.bashrc
echo '    if [ ! -f "$fname" ] ; then'          >> $HOME/.bashrc
echo '        cat > "${fname}"<<EOF'            >> $HOME/.bashrc
echo '#!/usr/bin/env python2'                   >> $HOME/.bashrc
echo 'from pwn import *'                        >> $HOME/.bashrc
echo 'context(arch = "i386", os = "linux")'     >> $HOME/.bashrc
echo ''                                         >> $HOME/.bashrc
echo ''                                         >> $HOME/.bashrc
echo 'EOF'                                      >> $HOME/.bashrc
echo '        chmod +x "${fname}"'              >> $HOME/.bashrc
echo '    fi'                                   >> $HOME/.bashrc
echo '        ${EDITOR} "${fname}" +'           >> $HOME/.bashrc
echo '}'                                        >> $HOME/.bashrc

# Install RunShellcode
git_clone https://github.com/RobertLarsen/RunShellcode.git
cd $HOME/.repositories/RunShellcode
sudo gcc -m32 -o /usr/bin/run_shellcode32 run_shellcode.c
sudo gcc      -o /usr/bin/run_shellcode64 run_shellcode.c

# Done
POST=$(date +%s)
echo "Installation took "$((POST-PRE))" seconds"
EOF

Vagrant.configure(2) do |config|
    config.vm.box = "puppetlabs/ubuntu-14.04-64-puppet"
    config.vm.provider "virtualbox" do |v|
        v.memory = 4096
        v.cpus = 2
    end
    config.vm.provision "shell", inline: $install, privileged: false
    config.vm.hostname = "pwnmachine"
end

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
sudo -E apt-get -y install git python-pip python3-pip python-dev        \
    build-essential python-software-properties gdb gdb-multiarch curl   \
    vim exuberant-ctags pyflakes cmake realpath tmux source-highlight   \
    libpq5 gcc-multilib libc6-i386 libc6-dev-i386 qemu-user-static      \
    libreadline-dev libssl-dev libpq-dev nmap libreadline5 ruby2.2      \
    libsqlite3-dev libpcap-dev openjdk-7-jre autoconf postgresql nasm   \
    pgadmin3 zlib1g-dev libxml2-dev libxslt1-dev ruby2.2-dev screen
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
git_clone git://github.com/RobertLarsen/WorkstationSetup.git

# Install Vim
HOME=$MY_HOME USER=$MY_NAME bash .repositories/WorkstationSetup/vim.sh

# Install pwntools + dependencies
git_clone git://github.com/Gallopsled/pwntools.git ${MY_HOME}
cd pwntools
sed -i "s/\\['splitw'\\]/\\['splitw', '-h'\\]/" pwnlib/util/misc.py
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

# ptrace_scope = 0
sudo sed -i 's/kernel.yama.ptrace_scope = 1/kernel.yama.ptrace_scope = 0/' /etc/sysctl.d/10-ptrace.conf
sudo service procps restart

# Create .gdbinit
echo 'set follow-fork-mode child'          >> /home/vagrant/.gdbinit
echo 'set disassembly-flavor intel'        >> /home/vagrant/.gdbinit
echo 'set auto-load safe-path /'           >> /home/vagrant/.gdbinit
echo 'set disable-randomization off'       >> /home/vagrant/.gdbinit

# Install voltron
sudo apt-get -y install libreadline6-dev python3-dev python3-setuptools python3-yaml
git_clone git://github.com/snare/voltron.git
cd $HOME/.repositories/voltron
sudo python3 setup.py install
echo "#source ~/.repositories/voltron/voltron/entry.py" >> /home/vagrant/.gdbinit
echo "#voltron init"                                    >> /home/vagrant/.gdbinit

# Install peda
git_clone git://github.com/zachriggle/peda.git
echo '#source ~/.repositories/peda/peda.py' >> /home/vagrant/.gdbinit

# Install pwndbg
git_clone git://github.com/zachriggle/pwndbg
git_clone git://github.com/aquynh/capstone
cd $HOME/.repositories/capstone
git checkout -t origin/next
sudo ./make.sh install
cd bindings/python
sudo python3 setup.py install # Ubuntu 14.04+, GDB uses Python3
sudo pip3 install pycparser # Use pip3 for Python3
echo "source ~/.repositories/pwndbg/gdbinit.py" >> /home/vagrant/.gdbinit

# Install qira
git_clone git://github.com/BinaryAnalysisPlatform/qira.git
cd $HOME/.repositories/qira
sed -i 's/sudo apt-get/sudo apt-get -y/g' tracers/qemu_build.sh
./install.sh

# Install radare2
git_clone git://github.com/radare/radare2
cd $HOME/.repositories/radare2
./sys/install.sh
sudo pip install r2pipe

# Install angr
sudo apt-get -y install python-dev libffi-dev build-essential virtualenvwrapper
sudo pip install angr --upgrade

# Install AFL
sudo apt-get -y install clang llvm
cd $HOME/.repositories
wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xvf afl-latest.tgz
rm afl-latest.tgz
(
  cd afl-*
  make
  # build clang-fast
  (
    cd llvm_mode
    make
  )
  sudo make install
)

# Install Metasploit
sudo gem2.2 install bundler
git_clone git://github.com/rapid7/metasploit-framework.git
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
echo '    ${EDITOR} "${fname}" +'               >> $HOME/.bashrc
echo '}'                                        >> $HOME/.bashrc

# Update .screenrc
cat > $HOME/.screenrc << SCREEN_END
startup_message off
vbell off
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%? %= %{g}][%{B} %m/%d %{W}%c %{g}]'
defscrollback 50000
SCREEN_END

# Install RunShellcode
git_clone git://github.com/RobertLarsen/RunShellcode.git
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
    # forward qira port
    config.vm.network "forwarded_port", guest: 3002, host: 3002
end

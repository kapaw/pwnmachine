# -*- mode: ruby -*-
# vi: set ft=ruby :

$install = <<EOF
PRE=$(date +%s)
MY_NAME=vagrant
MY_HOME=/home/${MY_NAME}
export DEBIAN_FRONTEND=noninteractive

# Install packages
sudo rm -rf /var/lib/apt/lists
sudo dpkg --add-architecture i386
sudo -E apt-get -y update
sudo -E apt-get -y upgrade
sudo -E apt-get -y install git python-pip python3-pip python-dev        \
    build-essential software-properties-common gdb gdb-multiarch curl   \
    vim exuberant-ctags pyflakes cmake tmux source-highlight            \
    libpq5 gcc-multilib libc6-i386 libc6-dev-i386 qemu-user-static      \
    libreadline-dev libssl-dev libpq-dev nmap libreadline5              \
    libsqlite3-dev libpcap-dev autoconf pgadmin3 zlib1g-dev libxml2-dev \
    libxslt1-dev screen ipython gdbserver binutils-{arm,mips}*          \
    binutils-multiarch libxml2-dev libxslt1-dev git libffi-dev          \
    libreadline-dev libtool debootstrap debian-archive-keyring          \
    libglib2.0-dev libpixman-1-dev libqt4-dev graphviz-dev              \
    nasm pandoc libtool-bin valgrind libfuzzer-7-dev
sudo -E pip install pip --upgrade

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

# Install pwntools + dependencies
git_clone https://github.com/Gallopsled/pwntools.git ${MY_HOME}
cd pwntools
sudo pip2 install -r requirements.txt
sudo python setup.py install
cd ${MY_HOME}

# Enable core dumps
ulimit -c 100000
echo 'vagrant     soft      core      unlimited' | sudo tee /etc/security/limits.conf

# ptrace_scope = 0
sudo sed -i 's/kernel.yama.ptrace_scope = 1/kernel.yama.ptrace_scope = 0/' /etc/sysctl.d/10-ptrace.conf
sudo service procps restart

# Create .gdbinit
echo 'set follow-fork-mode child'          >> ${MY_HOME}/.gdbinit
echo 'set disassembly-flavor intel'        >> ${MY_HOME}/.gdbinit
echo 'set auto-load safe-path /'           >> ${MY_HOME}/.gdbinit
echo 'set disable-randomization off'       >> ${MY_HOME}/.gdbinit

# Install voltron
sudo apt-get -y install libreadline6-dev python3-dev python3-setuptools python3-yaml
git_clone https://github.com/snare/voltron.git
cd ${MY_HOME}/.repositories/voltron
./install.sh
sed -i 's/\(.*voltron.*\)/#\1/' ${MY_HOME}/.gdbinit

# Install gef
git_clone https://github.com/hugsy/gef.git
sed -i 's/127.0.1.1/127.0.0.1/g' ${MY_HOME}/.repositories/gef/gef.py
echo '#source ~/.repositories/gef/gef.py' >> ${MY_HOME}/.gdbinit

# Install peda
git_clone https://github.com/longld/peda
echo '#source ~/.repositories/peda/peda.py' >> ${MY_HOME}/.gdbinit

# Install pwndbg
git_clone https://github.com/pwndbg/pwndbg.git
cd ${MY_HOME}/.repositories/pwndbg
sudo ./setup.sh

## Install qira (BUG: ubuntu 18.04 qemu)
#git_clone https://github.com/BinaryAnalysisPlatform/qira.git
#cd ${MY_HOME}/.repositories/qira
#sed -i 's/sudo apt-get/sudo apt-get -y/g' tracers/qemu_build.sh
#sed -i 's/.*pypi.python.org\\/packages\\/source\\/p\\/pyparsing.*/pyparsing/g' requirements.txt
#sudo ./install.sh

# Install radare2
git_clone https://github.com/radare/radare2
cd ${MY_HOME}/.repositories/radare2
./sys/user.sh
sudo -E pip install r2pipe --upgrade

# Install z3
git_clone https://github.com/Z3Prover/z3.git
cd ${MY_HOME}/.repositories/z3
sudo python scripts/mk_make.py --python
cd build
sudo make
sudo make install

# Install angr
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
mkvirtualenv --python=$(which python3) angr
pip install angr
deactivate

# Install ropper
git_clone https://github.com/sashs/ropper.git
cd ${MY_HOME}/.repositories/ropper
git submodule init
git submodule update
sudo -E pip install filebytes==0.9.18
sudo -E pip install keystone-engine
sudo -E pip install . --upgrade

# Install afl-fuzz
sudo apt-get -y install clang-7
cd ${MY_HOME}/.repositories
wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xvf afl-latest.tgz
rm afl-latest.tgz
(
  cd afl-*
  make
  # build clang-fast
  (
    cd llvm_mode
    CC=clang-7 LLVM_CONFIG=llvm-config-7 make
  )
  # build qemu mode (BUG: ubuntu 18.04 qemu)
  #(
  #  cd qemu_mode
  #  sudo apt install -y bison flex
  #  ./build_qemu_support.sh
  #)
  # build libdislocator
  (
    cd libdislocator
    make
  )
  # build libtokencap
  (
    cd libtokencap
    make
  )
  sudo make install
)

# Install honggfuzz
git_clone https://github.com/google/honggfuzz.git
sudo apt-get -y install libbfd-dev libunwind-dev
cd ${MY_HOME}/.repositories/honggfuzz
make
sudo make install

# Install radamsa
git_clone https://gitlab.com/akihe/radamsa.git
sudo apt-get -y install gcc make git wget
cd ${MY_HOME}/.repositories/radamsa
make
sudo make install

# Install zzuf
git_clone https://github.com/samhocevar/zzuf.git
cd ${MY_HOME}/.repositories/zzuf
./bootstrap
./configure
make
sudo make install

# Install unicorn engine
git_clone https://github.com/unicorn-engine/unicorn.git
cd ${MY_HOME}/.repositories/unicorn
make
sudo make install

# Install Intel Pin
cd ${MY_HOME}/.repositories/
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz
tar xf pin-*.tar.gz
rm pin-*.tar.gz
ln -s pin-* pin
echo "PIN_HOME=${MY_HOME}/.repositories/pin/" >> ${MY_HOME}/.bashrc

# Install DynamoRIO
cd ${MY_HOME}/.repositories/
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_7.1.0/DynamoRIO-Linux-7.1.0-1.tar.gz
tar xf DynamoRIO-Linux-*.tar.gz
rm DynamoRIO-Linux-*.tar.gz
ln -s DynamoRIO-Linux-* DynamoRIO
echo "DYNAMORIO_HOME=${MY_HOME}/.repositories/DynamoRIO/" >> ${MY_HOME}/.bashrc

# Add 'pwn' exploit template function to .bashrc
echo 'export EDITOR=vim'                                                                  >> ${MY_HOME}/.bashrc
echo 'function pwn(){'                                                                    >> ${MY_HOME}/.bashrc
echo '    target_bin="$1"'                                                                >> ${MY_HOME}/.bashrc
echo '    fname="exploit.py"'                                                             >> ${MY_HOME}/.bashrc
echo '    if [ ! -f "$fname" ] ; then'                                                    >> ${MY_HOME}/.bashrc
echo '        cat > "${fname}"<<EOF'                                                      >> ${MY_HOME}/.bashrc
echo '#!/usr/bin/env python'                                                              >> ${MY_HOME}/.bashrc
echo 'from pwn import *'                                                                  >> ${MY_HOME}/.bashrc
echo 'context.terminal = ["tmux", "splitw", "-h"]'                                        >> ${MY_HOME}/.bashrc
echo ''                                                                                   >> ${MY_HOME}/.bashrc
echo 'TARGET_BIN = ""'                                                                    >> ${MY_HOME}/.bashrc
echo 'HOST = "127.0.0.1"'                                                                 >> ${MY_HOME}/.bashrc
echo 'PORT = 1337'                                                                        >> ${MY_HOME}/.bashrc
echo ''                                                                                   >> ${MY_HOME}/.bashrc
echo 'c = None'                                                                           >> ${MY_HOME}/.bashrc
echo 'if "REMOTE" in args:'                                                               >> ${MY_HOME}/.bashrc
echo '    c = remote(HOST, PORT)'                                                         >> ${MY_HOME}/.bashrc
echo 'elif "GDB" in args:'                                                                >> ${MY_HOME}/.bashrc
echo '    c = gdb.debug(TARGET_BIN, """'                                                  >> ${MY_HOME}/.bashrc
echo '        c'                                                                          >> ${MY_HOME}/.bashrc
echo '        """)'                                                                       >> ${MY_HOME}/.bashrc
echo 'else:'                                                                              >> ${MY_HOME}/.bashrc
echo '    c = process(TARGET_BIN)'                                                        >> ${MY_HOME}/.bashrc
echo ''                                                                                   >> ${MY_HOME}/.bashrc
echo ''                                                                                   >> ${MY_HOME}/.bashrc
echo 'EOF'                                                                                >> ${MY_HOME}/.bashrc
echo '        target_escaped=$(echo $target_bin | sed "s/\\//\\\\\\\\\\//g")'             >> ${MY_HOME}/.bashrc
echo '        sed -i "s/\\(TARGET_BIN = \\"\\)\\(\\"\\)/\\1$target_escaped\\2/" "$fname"' >> ${MY_HOME}/.bashrc
echo '        chmod +x "${fname}"'                                                        >> ${MY_HOME}/.bashrc
echo '    fi'                                                                             >> ${MY_HOME}/.bashrc
echo '    grep -q "TARGET_BIN = \\"\\"" "${fname}"'                                       >> ${MY_HOME}/.bashrc
echo '    if [ "$?" -eq 0 ] ; then'                                                       >> ${MY_HOME}/.bashrc
echo '        ${EDITOR} -c "startinsert" "${fname}" "+call cursor(5,15)"'                 >> ${MY_HOME}/.bashrc
echo '    else'                                                                           >> ${MY_HOME}/.bashrc
echo '        ${EDITOR} "${fname}" +'                                                     >> ${MY_HOME}/.bashrc
echo '    fi'                                                                             >> ${MY_HOME}/.bashrc
echo '}'                                                                                  >> ${MY_HOME}/.bashrc

# Update .screenrc
cat > ${MY_HOME}/.screenrc << SCREEN_END
startup_message off
vbell off
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%? %= %{g}][%{B} %m/%d %{W}%c %{g}]'
defscrollback 50000
SCREEN_END

# Done
POST=$(date +%s)
echo "Installation took "$((POST-PRE))" seconds"
EOF

Vagrant.configure(2) do |config|
    config.vm.box = "ubuntu/bionic64"
    config.vm.box_check_update = false
    config.vm.provider "virtualbox" do |v|
        v.memory = 4096
        v.cpus = 4
    end
    config.vm.provision "shell", inline: $install, privileged: false
    config.vm.hostname = "pwnmachine"
    # forward qira port
    config.vm.network "forwarded_port", guest: 3002, host: 3002
    ENV['LC_ALL']="en_US.UTF-8"
end

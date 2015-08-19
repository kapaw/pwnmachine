# -*- mode: ruby -*-
# vi: set ft=ruby :

$install = <<EOF
MY_NAME=vagrant
MY_HOME=/home/${MY_NAME}

export DEBIAN_FRONTEND=noninteractive
#Install packages
sudo -E apt-get -y update
sudo -E apt-get -y upgrade
sudo -E apt-get -y install git python-pip python-dev build-essential \
    python-software-properties gdb curl vim exuberant-ctags pyflakes \
    cmake clang-3.5 software-properties-common

mkdir .repositories

function git_clone(){
    base=$(basename "${1}" | sed 's/\.git//g')
    git clone "${1}" ${MY_HOME}/.repositories/"${base}"
    if test -n "${2}"; then
        ln -s ${MY_HOME}/.repositories/"${base}" "${2}"/"${base}"
    fi
}

#Install pwntools + dependencies
git_clone https://github.com/Gallopsled/pwntools.git ${MY_HOME}
cd pwntools
sudo pip2 install -r requirements.txt
sudo python setup.py install
cd ${MY_HOME}

#Install many binutils
sudo apt-add-repository --yes ppa:pwntools/binutils
sudo apt-get update
sudo apt-get install binutils-{arm,i386,mips}-linux-gnu

#Install voltron (https://github.com/snare/voltron)
git_clone https://github.com/snare/voltron.git ${MY_HOME}
cat > .gdbinit <<GDB_EOF
set follow-fork-mode child
set disassembly-flavor intel

source ${MY_HOME}/voltron/dbgentry.py
voltron init
GDB_EOF
cd voltron
sudo python setup.py install
cd ${MY_HOME}

#Configure vim
mkdir -p .vim/autoload .vim/bundle
ctags-exuberant --fields=+S --sort=yes -f ${MY_HOME}/.vim/systags   -R /usr/include 2>/dev/null
curl -LSso .vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim
git_clone https://github.com/SirVer/ultisnips.git ${MY_HOME}/.vim/bundle
git_clone git://github.com/honza/vim-snippets.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/tpope/vim-fugitive.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/kevinw/pyflakes-vim.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/scrooloose/syntastic.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/Valloric/YouCompleteMe.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/bling/vim-airline.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/kien/ctrlp.vim.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/ervandew/supertab.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/juneedahamed/svnj.vim.git ${MY_HOME}/.vim/bundle
git_clone https://github.com/bruno-/vim-man.git ${MY_HOME}/.vim/bundle

cd .vim/bundle/YouCompleteMe
git submodule update --init --recursive
./install.sh --clang-completer
cd ${MY_HOME}


cat > .vim/vimrc <<VIM_EOF
execute pathogen#infect()

syntax on
colo elflord
set hlsearch
set incsearch
set expandtab
set tabstop=4
set shiftwidth=4
set ignorecase
set smartcase
set number
set si
filetype plugin indent on

autocmd FileType java map <F8> :!ant<CR>
autocmd FileType java map <F9> :!ant run<CR>
autocmd FileType cpp set tags+=~/.vim/systags
autocmd FileType cpp set omnifunc=ccomplete#Complete
autocmd FileType c set tags+=~/.vim/systags
autocmd FileType c set omnifunc=ccomplete#Complete
autocmd FileType php set omnifunc=phpcomplete#CompletePHP
autocmd FileType xml set omnifunc=xmlcomplete#CompleteXML
autocmd FileType html set omnifunc=htmlcomplete#CompleteTags
map <F8> :make<CR>
map <F9> :make<CR>

"YCM
let g:ycm_key_list_select_completion = ['<C-n>', '<Down>']
let g:ycm_key_list_previous_completion = ['<C-p>', '<Up>']
let g:SuperTabDefaultCompletionType = '<C-n>'

"UltiSnips
let UltiSnipsEditSplit="vertical"
let g:UltiSnipsExpandTrigger="<tab>"
let g:UltiSnipsJumpForwardTrigger="<tab>"
let g:UltiSnipsJumpBackwardTrigger="<s-tab>"

VIM_EOF
ln -s .vim/vimrc .vimrc
sudo chown -R ${MY_NAME}.${MY_NAME} ${MY_HOME}


EOF

Vagrant.configure(2) do |config|
    config.vm.box = "puphpet/ubuntu1404-x64"
    config.vm.provision "shell", inline: $install
end
